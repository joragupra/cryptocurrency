import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TxHandler {

    private UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    UTXOPool getUtxoPool() {
        return this.utxoPool;
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        if (hasNegativeValueInOutput(tx)) {
            return false;
        }
        if (claimsOutputsOutsideCurrentPool(tx)) {
            return false;
        }
        if (hasInvalidSignature(tx)) {
            return false;
        }
        if (claimsSameOutputMoreThanOnce(tx)) {
            return false;
        }
        if (calculateOutputValues(tx) > calculateInputValues(tx)) {
            return false;
        }
        return true;
    }

    private boolean hasNegativeValueInOutput(Transaction tx) {
        return tx.getOutputs().stream().anyMatch(output -> output.value < 0);
    }

    private boolean claimsOutputsOutsideCurrentPool(Transaction tx) {
        return !tx.getInputs().stream().allMatch(input -> getUtxoPool().contains(new UTXO(input.prevTxHash, input.outputIndex)));
    }

    private boolean hasInvalidSignature(Transaction tx) {
        AtomicInteger index = new AtomicInteger();
        return tx.getInputs().stream().anyMatch(input -> !Crypto.verifySignature(findInCurrentPool(input).address, tx.getRawDataToSign(index.getAndIncrement()), input.signature));
    }

    private boolean claimsSameOutputMoreThanOnce(Transaction tx) {
        Stream<UTXO> claimedOutputs = tx.getInputs().stream().map(input -> new UTXO(input.prevTxHash, input.outputIndex));
        Stream<UTXO> claimedOutputsWithoutRepetitions = tx.getInputs().stream().map(input -> new UTXO(input.prevTxHash, input.outputIndex)).distinct();

        return claimedOutputsWithoutRepetitions.count() != claimedOutputs.count();
    }

    private double calculateInputValues(Transaction tx) {
        return tx.getInputs().stream().mapToDouble(input -> findInCurrentPool(input).value).reduce(0.0, Double::sum);
    }

    private double calculateOutputValues(Transaction tx) {
        return tx.getOutputs().stream().mapToDouble(output -> output.value).reduce(0.0, Double::sum);
    }

    private Transaction.Output findInCurrentPool(Transaction.Input input) {
        return getUtxoPool().getTxOutput(new UTXO(input.prevTxHash, input.outputIndex));
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> appliedTransactions = new ArrayList<>();
        List<Transaction> transactions = Arrays.asList(possibleTxs);

        transactions.stream().filter(this::isValidTx).forEach(tx -> {
            this.utxoPool = applyTx(tx);
            appliedTransactions.add(tx);
        });

        return appliedTransactions.toArray(new Transaction[]{});
    }

    UTXOPool applyTx(Transaction tx) {
        return applyTx(tx, getUtxoPool());
    }

    private UTXOPool applyTx(Transaction tx, UTXOPool utxoPool) {
        if (!isValidTx(tx)) {
            throw new IllegalArgumentException("Cannot apply an invalid transaction");
        }

        UTXOPool updatedPool = new UTXOPool(utxoPool);

        tx.getInputs().stream().map(input -> new UTXO(input.prevTxHash, input.outputIndex)).forEach(updatedPool::removeUTXO);

        AtomicInteger index = new AtomicInteger();
        tx.getOutputs().stream().map(output -> new UTXO(tx.getHash(), index.getAndIncrement())).forEach(utxo -> updatedPool.addUTXO(utxo, tx.getOutput(utxo.getIndex())));

        return updatedPool;
    }

}

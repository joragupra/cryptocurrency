import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class MaxFeeTxHandler {

    private TxHandler simpleTxHandler;

    MaxFeeTxHandler(TxHandler simpleTxHandler) {
        this.simpleTxHandler = simpleTxHandler;
    }

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public MaxFeeTxHandler(UTXOPool utxoPool) {
        this.simpleTxHandler = new TxHandler(utxoPool);
    }

    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        return simpleTxHandler.handleTxs(sortByTxFee(possibleTxs));
    }

    UTXOPool getUtxoPool() {
        return this.simpleTxHandler.getUtxoPool();
    }

    Transaction[] sortByTxFee(Transaction[] transactions) {
        return Arrays.stream(transactions)
                .sorted((tx1, tx2) -> calculateTxFee(tx1) > calculateTxFee(tx2) ? -1 : 1)
                .collect(Collectors.toList())
                .toArray(new Transaction[] {});
    }

    double calculateTxFee(Transaction tx) {
        if (!simpleTxHandler.isValidTx(tx)) {
            return 0.0;
        }

        double inputValues = tx.getInputs().stream()
                .map(input -> new UTXO(input.prevTxHash, input.outputIndex))
                .map(utxo -> simpleTxHandler.getUtxoPool().getTxOutput(utxo))
                .mapToDouble(output -> output.value)
                .sum();
        double outputValues = tx.getOutputs().stream()
                .mapToDouble(output -> output.value)
                .sum();

        return inputValues - outputValues;
    }
}

import org.junit.Test;
import sun.security.x509.X509Key;

import java.math.BigInteger;
import java.security.*;
import java.util.Random;

import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static testutils.KeyFactory.getKey;

public class MaxFeeTxHandlerTest {

    @Test
    public void testConstructor() {
        UTXOPool originalUtxoPool = new UTXOPool();
        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(originalUtxoPool);

        UTXO utxo = new UTXO(new byte[]{}, 0);
        Transaction.Output output = new Transaction().new Output(0.0, new X509Key());

        originalUtxoPool.addUTXO(utxo, output);

        assertTrue(originalUtxoPool.contains(utxo));
        assertFalse(txHandler.getUtxoPool().contains(utxo));
    }

    @Test
    public void testCalculateTxFee() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        double inputValue = 10.0;
        double outputValue1 = 1.0;
        double outputValue2 = 1.0;

        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(inputValue, initialOwner);

        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(outputValue1, newOwner.getPublic());
        tx1.addOutput(outputValue2, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(utxoPool);

        assertEquals(inputValue - outputValue1 - outputValue2, txHandler.calculateTxFee(tx1), 0.0);
    }

    @Test
    public void testCalculateTxFee_ShouldReturn0_WhenTxIsNotValid() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        KeyPair originalOwner = getKey();
        Transaction tx = createTxOutOfThinHair(1.0, originalOwner);

        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(tx.getHash(),0);
        utxoPool.addUTXO(utxo, tx.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(tx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(originalOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(utxoPool);

        assertEquals(0.0, txHandler.calculateTxFee(tx1), 0.0);
    }

    @Test
    public void testSortByTxFee() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        //create transaction to give 10 coins to the initial owner
        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(10.0, initialOwner);

        KeyPair anotherInitialOwner = getKey();
        Transaction initialTx2= createTxOutOfThinHair(10.0, anotherInitialOwner);

        // The transaction output of the root transaction is unspent output
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));
        UTXO utxo2 = new UTXO(initialTx2.getHash(),0);
        utxoPool.addUTXO(utxo2, initialTx2.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(2, newOwner.getPublic());
        tx1.addOutput(2, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        Transaction tx2 = new Transaction();
        tx2.addOutput(1, newOwner.getPublic());
        tx2.addOutput(1, newOwner.getPublic());
        tx2.addInput(initialTx.getHash(), 0);

        Signature signature2 = Signature.getInstance("SHA256withRSA");
        signature2.initSign(initialOwner.getPrivate());
        signature2.update(tx2.getRawDataToSign(0));
        byte[] sig2 = signature2.sign();
        tx2.addSignature(sig2, 0);
        tx2.finalize();

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(utxoPool);

        Transaction[] unsortedTransactions = new Transaction[] {tx1, tx2};
        Transaction[] sortedTransactions = txHandler.sortByTxFee(unsortedTransactions);

        assertEquals(unsortedTransactions.length, sortedTransactions.length);
        assertEquals(unsortedTransactions[1], sortedTransactions[0]);
        assertEquals(unsortedTransactions[0], sortedTransactions[1]);
    }

    @Test
    public void testHandleTxs_ShouldSortByTxFeeAndDelegateToSimpleTxHandler() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        //create transaction to give 10 coins to the initial owner
        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(10.0, initialOwner);

        KeyPair anotherInitialOwner = getKey();
        Transaction initialTx2= createTxOutOfThinHair(10.0, anotherInitialOwner);

        // The transaction output of the root transaction is unspent output
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(2, newOwner.getPublic());
        tx1.addOutput(2, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        Transaction tx2 = new Transaction();
        tx2.addOutput(1, newOwner.getPublic());
        tx2.addOutput(1, newOwner.getPublic());
        tx2.addInput(initialTx.getHash(), 0);

        Signature signature2 = Signature.getInstance("SHA256withRSA");
        signature2.initSign(initialOwner.getPrivate());
        signature2.update(tx2.getRawDataToSign(0));
        byte[] sig2 = signature.sign();
        tx2.addSignature(sig2, 0);
        tx2.finalize();

        TxHandler simpleTxHandler = mock(TxHandler.class);
        when(simpleTxHandler.isValidTx(any(Transaction.class))).thenReturn(true);
        when(simpleTxHandler.getUtxoPool()).thenReturn(utxoPool);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(simpleTxHandler);

        txHandler.handleTxs(new Transaction[] {tx1, tx2});

        verify(simpleTxHandler, times(1)).handleTxs(new Transaction[] {tx2, tx1});
    }

    private Transaction createTxOutOfThinHair(double numCoins, KeyPair initialOwner) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Transaction initialTx = new Transaction();
        initialTx.addOutput(numCoins, initialOwner.getPublic());
        // that value has no meaning, but tx.getRawDataToSign(0) will access in.prevTxHash;
        Random r = new Random();
        byte[] initialHash = BigInteger.valueOf((10000 + r.nextLong()) % 10000000).toByteArray();
        initialTx.addInput(initialHash, 0);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(initialTx.getRawDataToSign(0));
        byte[] sig = signature.sign();
        initialTx.addSignature(sig, 0);
        initialTx.finalize();
        return initialTx;
    }
}

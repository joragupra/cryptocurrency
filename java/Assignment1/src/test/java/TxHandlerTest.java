
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import sun.security.x509.X509Key;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.UUID;

import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.commons.codec.binary.Base64;

public class TxHandlerTest {

    public static KeyPair getKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        return keyGen.generateKeyPair();
    }

    @Test
    public void testConstructor() {
        UTXOPool originalUtxoPool = new UTXOPool();
        TxHandler txHandler = new TxHandler(originalUtxoPool);

        UTXO utxo = new UTXO(new byte[]{}, 0);
        Transaction.Output output = new Transaction().new Output(0.0, new X509Key());

        originalUtxoPool.addUTXO(utxo, output);

        assertTrue(originalUtxoPool.contains(utxo));
        assertFalse(txHandler.getUtxoPool().contains(utxo));
    }


    @Test
    public void testIsValidTx_WhenSomeOutputValueIsNegative() {
        TxHandler txHandler = new TxHandler(new UTXOPool());

        Transaction tx = new Transaction();
        tx.addOutput(-1.0, new X509Key());

        assertFalse(txHandler.isValidTx(tx));
    }

    @Test
    public void testIsValidTx_WhenInputValuesAreLessThanOutputValues() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
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

        TxHandler txHandler = new TxHandler(utxoPool);

        assertFalse(txHandler.isValidTx(tx1));
    }

    @Test
    public void testIsValidTx_WhenClaimedOutputNotFound() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(10.0, initialOwner);

        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));

        Transaction anotherInitialTxNotInPool = createTxOutOfThinHair(10.0, initialOwner);

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(anotherInitialTxNotInPool.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        assertFalse(txHandler.isValidTx(tx1));
    }

    @Test
    public void testIsValidTx_WhenOutputClaimedMoreThanOnce() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(10.0, initialOwner);

        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.addSignature(sig, 1);
        tx1.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        assertFalse(txHandler.isValidTx(tx1));
    }

    @Test
    public void testIsValidTx_WhenAnInputSignatureIsNotValid() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(10.0, initialOwner);

        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        byte tmp = sig[0];
        sig[0] = sig[1];
        sig[1] = tmp;
        tx1.addSignature(sig, 0);
        tx1.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        assertFalse(txHandler.isValidTx(tx1));
    }

    @Test
    public void testIsValidTx() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        //create transaction to give 10 coins to the initial owner
        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(10.0, initialOwner);

        // The transaction output of the root transaction is unspent output
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        assertTrue(txHandler.isValidTx(tx1));
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

    @Test(expected = IllegalArgumentException.class)
    public void testApplyTx_WhenTheTransactionIsNotValid() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(10.0, initialOwner);

        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        byte tmp = sig[0];
        sig[0] = sig[1];
        sig[1] = tmp;
        tx1.addSignature(sig, 0);
        tx1.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        txHandler.applyTx(tx1);
    }

    @Test
    public void testApplyTx_RemovesTxInputFromPool() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        //create transaction to give 10 coins to the initial owner
        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(10.0, initialOwner);

        // The transaction output of the root transaction is unspent output
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        UTXOPool updatedPool = txHandler.applyTx(tx1);

        assertFalse(updatedPool.contains(new UTXO(tx1.getInput(0).prevTxHash, tx1.getInput(0).outputIndex)));
    }

    @Test
    public void testApplyTx_AddsTxOutputToPool() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        //create transaction to give 10 coins to the initial owner
        KeyPair initialOwner = getKey();
        Transaction initialTx = createTxOutOfThinHair(10.0, initialOwner);

        // The transaction output of the root transaction is unspent output
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(initialTx.getHash(),0);
        utxoPool.addUTXO(utxo, initialTx.getOutput(0));

        KeyPair newOwner = getKey();

        Transaction tx1 = new Transaction();
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        UTXOPool updatedPool = txHandler.applyTx(tx1);

        assertTrue(updatedPool.contains(new UTXO(tx1.getHash(), 0)));
        assertEquals(tx1.getOutput(0), updatedPool.getTxOutput(new UTXO(tx1.getHash(), 0)));
        assertTrue(updatedPool.contains(new UTXO(tx1.getHash(), 1)));
        assertEquals(tx1.getOutput(1), updatedPool.getTxOutput(new UTXO(tx1.getHash(), 1)));
    }

    @Test
    public void testApplyTx_KeepsNotClaimedUTXOsInPool() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
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
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        UTXOPool updatedPool = txHandler.applyTx(tx1);

        assertTrue(updatedPool.contains(utxo2));
        assertEquals(initialTx2.getOutput(0), updatedPool.getTxOutput(utxo2));
    }

    @Test
    public void testHandleTxs_AppliesValidTx() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
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
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addInput(initialTx.getHash(), 0);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(initialOwner.getPrivate());
        signature.update(tx1.getRawDataToSign(0));
        byte[] sig = signature.sign();
        tx1.addSignature(sig, 0);
        tx1.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        Transaction[] transactions = new Transaction[] {tx1};

        txHandler.handleTxs(transactions);

        UTXOPool updatedPool = txHandler.getUtxoPool();

        //removes inputs
        assertFalse(updatedPool.contains(new UTXO(tx1.getInput(0).prevTxHash, tx1.getInput(0).outputIndex)));

        //adds outputs
        assertTrue(updatedPool.contains(new UTXO(tx1.getHash(), 0)));
        assertEquals(tx1.getOutput(0), updatedPool.getTxOutput(new UTXO(tx1.getHash(), 0)));
        assertTrue(updatedPool.contains(new UTXO(tx1.getHash(), 1)));
        assertEquals(tx1.getOutput(1), updatedPool.getTxOutput(new UTXO(tx1.getHash(), 1)));

        //keeps not used
        assertTrue(updatedPool.contains(utxo2));
        assertEquals(initialTx2.getOutput(0), updatedPool.getTxOutput(utxo2));
    }

    @Test
    public void testHandleTxs_IgnoresInvalidTx() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
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
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
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
        byte tmp = sig2[0];
        sig2[0] = sig2[1];
        sig2[1] = tmp;
        tx2.addSignature(sig2, 0);
        tx2.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        Transaction[] transactions = new Transaction[] {tx1, tx2};

        txHandler.handleTxs(transactions);

        UTXOPool updatedPool = txHandler.getUtxoPool();

        assertFalse(updatedPool.contains(new UTXO(tx2.getHash(), 0)));
        assertFalse(updatedPool.contains(new UTXO(tx2.getHash(), 1)));
    }

    @Test
    public void testHandleTxs_ReturnsOnlyAppliedTx() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
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
        tx1.addOutput(1, newOwner.getPublic());
        tx1.addOutput(1, newOwner.getPublic());
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
        byte tmp = sig2[0];
        sig2[0] = sig2[1];
        sig2[1] = tmp;
        tx2.addSignature(sig2, 0);
        tx2.finalize();

        TxHandler txHandler = new TxHandler(utxoPool);

        Transaction[] transactions = new Transaction[] {tx1, tx2};

        Transaction[] appliedTx = txHandler.handleTxs(transactions);

        assertEquals(1, appliedTx.length);
        assertEquals(tx1, appliedTx[0]);
    }

}

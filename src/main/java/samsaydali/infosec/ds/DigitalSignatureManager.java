package samsaydali.infosec.ds;

import samsaydali.infosec.utils.Base64Utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DigitalSignatureManager {

    private static final String SIGNING_ALGORITHM = "SHA256withRSA";
    private final String signingAlgorithm;

    public DigitalSignatureManager() {
        this.signingAlgorithm = SIGNING_ALGORITHM;
    }

    public DigitalSignatureManager(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    public String createDigitalSignature(byte[] input, PrivateKey privateKey) throws Exception {
        byte[] signature = createDigitalSignatureBytes(input, privateKey);
        return Base64Utils.bytesToB64String(signature);
    }

    public String createDigitalSignature(String input, PrivateKey privateKey) throws Exception {
        byte[] in = input.getBytes();
        return createDigitalSignature(in, privateKey);
    }

    public byte[] createDigitalSignatureBytes(byte[] input, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(signingAlgorithm);
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    public byte[] createDigitalSignatureBytes(String input, PrivateKey privateKey) throws Exception {
        byte[] in = input.getBytes();
        return createDigitalSignatureBytes(in, privateKey);
    }

    public boolean verifyDigitalSignature(byte[] input, byte[] signatureToVerify, PublicKey publicKey) throws Exception{
        Signature signature = Signature.getInstance(signingAlgorithm);
        signature.initVerify(publicKey);
        signature.update(input);
        return signature.verify(signatureToVerify);
    }

    public boolean verifyDigitalSignature(String input, String signatureToVerify, PublicKey publicKey) throws Exception{
        byte[] in = input.getBytes();
        byte[] signature = Base64Utils.b64StringToBytes(signatureToVerify);
        return verifyDigitalSignature(in, signature, publicKey);
    }


}

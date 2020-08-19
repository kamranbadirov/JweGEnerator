package com.JweGenerator.JweGenerator;


import com.congerotechnology.crypto.enums.JWTType;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;

import com.congerotechnology.crypto.CongeroLicense;
import com.congerotechnology.crypto.KeyPair;
import org.springframework.stereotype.Service;


import java.security.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

import static java.util.UUID.randomUUID;
import static org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256;
import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.RSA_OAEP;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_USING_SHA256;

@Service
public class JweGeneratorService {
    public JweGeneratorService() throws NoSuchAlgorithmException {
    }

    KeyPair issuerKeyPair = new KeyPair("keys/issuer/private_key_pkcs8_to_sing.pem", "keys/issuer/public_key_to_encrypt.pem");
    KeyPair tenantKeypair = new KeyPair("keys/tenant/private_key_pkcs8_to_decrypt.pem", "keys/tenant/public_key_to_verify_sign.pem");

    //helper method to set expiration claim
    private void setExpStartClaim(JweGenerateRequestBody payload, JwtClaims claims) throws ParseException {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        if (payload.getExpiration()!=null){
            Date expirationTimestamp = formatter.parse(payload.getExpiration());
            claims.setExpirationTime(NumericDate.fromMilliseconds(expirationTimestamp.getTime()));
        }
        else {
            Calendar c = Calendar.getInstance();
            c.add(Calendar.DAY_OF_MONTH, 1);
            c.set(Calendar.HOUR_OF_DAY, 0);
            c.set(Calendar.MINUTE, 0);
            c.set(Calendar.SECOND, 0);
            c.set(Calendar.MILLISECOND, 0);
            claims.setExpirationTime(NumericDate.fromMilliseconds(c.getTimeInMillis()));
        }

        if(payload.getStartTime()!=null){
            Date startTimestamp = formatter.parse(payload.getStartTime());
            claims.setNotBefore(NumericDate.fromMilliseconds(startTimestamp.getTime()));
        }
        else{
            claims.setNotBefore(NumericDate.fromMilliseconds(System.currentTimeMillis()));
        }

    }

    public String JWEGenerator( JweGenerateRequestBody genPayload) throws JoseException, ParseException {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("http://congerotechnology.com");
        claims.setIssuedAtToNow();

        //set startTime and expirationTime
        setExpStartClaim(genPayload, claims);
        claims.setGeneratedJwtId();
        claims.setSubject(JWTType.LICENSE.toString());
        claims.setClaim("tenantName", genPayload.getTenantName());
        claims.setClaim("tenantId" , genPayload.getTenantId());

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(issuerKeyPair.getPrivateKey());
        jws.setKeyIdHeaderValue(randomUUID().toString());
        jws.setAlgorithmHeaderValue(RSA_USING_SHA256);
        String jwSigned =  jws.getCompactSerialization();

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(issuerKeyPair.getPublicKey());
        jwe.setKeyIdHeaderValue(randomUUID().toString());
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setPayload(jwSigned);


        return jwe.getCompactSerialization();

    }
    public JwtClaims decrypt(JwePayload jwe) throws JoseException, NoSuchAlgorithmException {

        CongeroLicense license = new CongeroLicense(tenantKeypair);
        return license.decrypt(jwe.getJwe());
    }


}

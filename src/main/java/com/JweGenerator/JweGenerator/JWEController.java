package com.JweGenerator.JweGenerator;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import com.congerotechnology.crypto.models.Tenant;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@RestController
@RequestMapping("/jwe")
public class JWEController {

    @Autowired
    JweGeneratorService jweService;


    //change to post; with tenantname and id, expiration;
    @PostMapping("/generate")
    String JweGenerator(@RequestBody JweGenerateRequestBody genPayload ) throws JoseException, NoSuchAlgorithmException, ParseException {
        return jweService.JWEGenerator(genPayload);
    }


    //input payload jwe (can be as header);
    @PostMapping("/decrypt")
    JwtClaims decrypt(@RequestBody JwePayload jwepayload) throws JoseException, NoSuchAlgorithmException {
        return jweService.decrypt(jwepayload);
    }


}

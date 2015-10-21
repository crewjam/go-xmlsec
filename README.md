# go-xmlsec

[![Build Status](https://travis-ci.org/crewjam/go-xmlsec.svg?branch=master)](https://travis-ci.org/crewjam/go-xmlsec)

[![](https://godoc.org/github.com/crewjam/go-xmlsec?status.png)](http://godoc.org/github.com/crewjam/go-xmlsec)

A (partial) wrapper for [xmlsec](https://www.aleksey.com/xmlsec).

# Signing (xmldsig)

## Signing Example

    key, _ := ioutil.ReadFile("saml.key")
    doc, _ := ioutil.ReadAll(os.Stdin)
    signedDoc, err := xmldsig.Sign(key, doc)
    os.Stdout.Write(signedDoc)

## Verifying Example

    key, _ := ioutil.ReadFile("saml.crt")
    doc, _ := ioutil.ReadAll(os.Stdin)
    err := xmldsig.Verify(key, doc)
    if err == xmldsig.ErrVerificationFailed {
      os.Exit(1)
    }

# Encryption (xmlenc)

## Encryption Example

    ctx := xmlenc.Context{}
    cert, _ := ioutil.ReadFile("saml.cert.pem")
    err := ctx.AddCert(cert)
    tmplDoc := []byte(``<?xml version="1.0" encoding="UTF-8"?>
    <!--
    XML Security Library example: Original XML doc file before encryption (encrypt3 example).
    -->
    <Envelope xmlns="urn:envelope">
      <Data>
        Hello, World!
      </Data>
      <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
          <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <!--<ds:KeyName>aes</ds:KeyName>-->
            <xenc:EncryptedKey Id="aes" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
              <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
                <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
              </xenc:EncryptionMethod>
              <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                <xenc:CipherValue></xenc:CipherValue>
              </xenc:CipherData>
            </xenc:EncryptedKey>
          </ds:KeyInfo>
          <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
            <xenc:CipherValue></xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedData>
    </Envelope>`)
    ciphertext, err := ctx.Encrypt(docStr, []byte("Hello, World!"))

## Decryption Example

    ctx := xmlenc.Context{}
    key, _ := ioutil.ReadFile("saml.key.pem")
    err := ctx.AddKey(key)
    plaintext, err := ctx.Decrypt(ciphertext)

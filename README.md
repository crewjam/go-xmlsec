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

## Decrypting Example

    key, _ := ioutil.ReadFile("saml.key")
    doc, _ := ioutil.ReadAll(os.Stdin)
    plaintextDoc, err := xmlenc.Decrypt(key, doc)
    os.Stdout.Write(plaintextDoc)

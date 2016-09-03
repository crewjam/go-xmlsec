# go-xmlsec

[![](https://godoc.org/github.com/crewjam/go-xmlsec?status.png)](http://godoc.org/github.com/crewjam/go-xmlsec) [![Build Status](https://travis-ci.org/crewjam/go-xmlsec.svg?branch=master)](https://travis-ci.org/crewjam/go-xmlsec)

A partial wrapper for [xmlsec](https://www.aleksey.com/xmlsec). 

As seems to be the case for many things in the XMLish world, the xmldsig and xmlenc standards are more complex that may be nessesary. This library is as general as I could reasonably make it with an eye towards supporting the parts of the standards that are needed to support a SAML implementation. If there are missing bits you feel you need, please raise an issue or submit a pull request. 

# Examples

## Signing

    key, _ := ioutil.ReadFile("saml.key")
    doc, _ := ioutil.ReadAll(os.Stdin)
    signedDoc, err := Sign(key, doc, SignatureOptions{})
    os.Stdout.Write(signedDoc)

## Verifying

    key, _ := ioutil.ReadFile("saml.crt")
    doc, _ := ioutil.ReadAll(os.Stdin)
    err := xmldsig.Verify(key, doc, SignatureOptions{})
    if err == xmldsig.ErrVerificationFailed {
      os.Exit(1)
    }

## Decrypting

    key, _ := ioutil.ReadFile("saml.key")
    doc, _ := ioutil.ReadAll(os.Stdin)
    plaintextDoc, err := Decrypt(key, doc)
    os.Stdout.Write(plaintextDoc)

## Encrypting

    key, _ := ioutil.ReadFile("saml.crt")
    doc, _ := ioutil.ReadAll(os.Stdin)
    encryptedDoc, err := Encrypt(key, doc, EncryptOptions{})
    os.Stdout.Write(encryptedDoc)

# Install

This package uses cgo to wrap libxmlsec. As such, you'll need libxmlsec headers and a C compiler to make it work. On linux, this might look like:

    $ apt-get install libxml2-dev libxmlsec1-dev
    $ go get github.com/crewjam/go-xmlsec

On Mac with homebrew, this might look like:

    $ brew install libxmlsec1 libxml2 pkg-config
    $ go get github.com/crewjam/go-xmlsec



# go-xmlsec

A (partial) wrapper for [xmlsec](https://www.aleksey.com/xmlsec).

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
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/crewjam/go-xmlsec"
)

func main() {
	doVerify := flag.Bool("v", false, "verify the document")
	doSign := flag.Bool("s", false, "sign the document")
	keyPath := flag.String("k", "", "the path to the key")
	xmlFile := flag.String("x", "", "the path to the xml file")
	flag.Parse()

	if !*doVerify && !*doSign {
		fmt.Println("you must specify -v to verify or -s to sign")
		os.Exit(1)
	}
	if *keyPath == "" {
		fmt.Println("you must specify a key file")
		os.Exit(1)
	}

	key, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	buf, err := readXml(xmlFile)

	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	if *doSign {
		signedBuf, err := xmlsec.Sign(key, buf, xmlsec.SignatureOptions{})
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(signedBuf)
	}

	if *doVerify {
		err := xmlsec.Verify(key, buf, xmlsec.SignatureOptions{})
		if err == xmlsec.ErrVerificationFailed {
			fmt.Println("signature is not correct")
			os.Exit(1)
		}
		if err != nil {
			fmt.Printf("error: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("signature is correct")
	}
}

func readXml(xmlFileName *string) ([]byte, error) {
	if *xmlFileName == "" {
		return ioutil.ReadAll(os.Stdin)
	} else {
		return ioutil.ReadFile(*xmlFileName)
	}
}

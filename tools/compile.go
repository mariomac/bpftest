package main

import (
	"fmt"
	"github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/elf"
	"io/ioutil"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: compile <input_file.c> <output_file.elf>")
		os.Exit(-1)
	}

	file, err := ioutil.ReadFile("./netdump.bcc.c")
	exitOnErr(err)


	m := bcc.NewModule(string(file), []string{})
	defer m.Close()

	m.
}

func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(-1)
	}
}

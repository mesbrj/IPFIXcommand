package main

/*
typedef struct{
	unsigned char a;
	char b;
	int c;
	unsigned int d;
	char e[10];
}unpacked;

#pragma pack(1)
typedef struct{
	unsigned char a;
	char b;
	int c;
	unsigned int d;
	char e[10];
}packed;

*/
import "C"
import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
)

func main() {
	unpack := C.packed{}
	pack := C.packed{}

	fmt.Println()
	fmt.Println("Printing the structure of the unpacked struct")
	fmt.Println()
	spew.Dump(unpack)

	fmt.Println()
	fmt.Println("Printing the structure of the packed struct")
	fmt.Println()
	spew.Dump(pack)
}

package redact_test

import (
	"fmt"
	"log"

	"go.iscode.ca/redact/pkg/redact"
	"go.iscode.ca/redact/pkg/redact/overwrite"
)

func ExampleOpt_Redact() {
	red := redact.New(redact.WithRules(`[[rules]]
id = "crypt-password-hash"
description = "Detected a password hash"
regex = '''\$(?:[a-zA-Z0-9]+)\$([^\s:]+)'''
`))
	redacted, err := red.Redact("root:$6$d468dc01f1cd655d$1c0a188389f4db6399265080815ac488ea65c3295a18d2d7da3ce5e8ef082362adeedec9b69.9704d4d188:18515:0:99999:7:::")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(redacted)
	// Output: root:$6$**REDACTED**:18515:0:99999:7:::
}

func ExampleOpt_Redact_mask() {
	red := redact.New(redact.WithRules(`[[rules]]
id = "crypt-password-hash"
description = "Detected a password hash"
regex = '''\$(?:[a-zA-Z0-9]+)\$([^\s:]+)'''
`),
		redact.WithOverwrite(&overwrite.Mask{Char: byte('*')}),
	)
	redacted, err := red.Redact("root:$6$d468dc01f1cd655d$1c0a188389f4db6399265080815ac488ea65c3295a18d2d7da3ce5e8ef082362adeedec9b69.9704d4d188:18515:0:99999:7:::")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(redacted)
	// Output: root:$6$*******************************************************************************************************:18515:0:99999:7:::
}

func ExampleOpt_Redact_unmasked() {
	red := redact.New(redact.WithRules(`[[rules]]
id = "crypt-password-hash"
description = "Detected a password hash"
regex = '''\$(?:[a-zA-Z0-9]+)\$([^\s:]+)'''
`),
		redact.WithOverwrite(&overwrite.Mask{Char: byte('*'), Unmasked: 10}),
	)
	redacted, err := red.Redact("root:$6$d468dc01f1cd655d$1c0a188389f4db6399265080815ac488ea65c3295a18d2d7da3ce5e8ef082362adeedec9b69.9704d4d188:18515:0:99999:7:::")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(redacted)
	// Output: root:$6$d468d*********************************************************************************************4d188:18515:0:99999:7:::
}

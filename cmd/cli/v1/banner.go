package main

import (
	"fmt"
	"io"
)

const bannerTitle = "frameseven CLI v1 - offensive web scanner"

const cliBanner = `
                 (` + "`" + `-').-> (` + "`" + `-')  _         _  (` + "`" + `-')
                 (OO )__  ( OO).-/  <-.    \-.(OO )
                ,--. ,'-'(,------.,--. )   _.'    \
                |  | |  | |  .---'|  (` + "`" + `-')(_...--''
                |  ` + "`" + `-'  |(|  '--. |  |OO )|  |_.'
                |  .-.  | |  .--'(|  '__ ||  .___.
                |  | |  | |  ` + "`" + `---.|     |'|  |
                ` + "`" + `--' ` + "`" + `--' ` + "`" + `------'` + "`" + `-----' ` + "`" + `--'
                            FrameSeven v1.0.0 Version
`

func writeBanner(output io.Writer) {
	fmt.Fprint(output, cliBanner)
}

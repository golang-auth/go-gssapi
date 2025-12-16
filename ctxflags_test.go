// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlagList(t *testing.T) {
	flags := ContextFlagConf | ContextFlagMutual | ContextFlagDeleg
	flaglist := FlagList(flags)

	assert.ElementsMatch(t, []ContextFlag{ContextFlagConf, ContextFlagMutual, ContextFlagDeleg}, flaglist)
}

func TestFlagName(t *testing.T) {
	assert.Equal(t, "Delegation", flagName(ContextFlagDeleg))
	assert.Equal(t, "Mutual authentication", flagName(ContextFlagMutual))
	assert.Equal(t, "Message replay detection", flagName(ContextFlagReplay))
	assert.Equal(t, "Out of sequence message detection", flagName(ContextFlagSequence))
	assert.Equal(t, "Confidentiality", flagName(ContextFlagConf))
	assert.Equal(t, "Integrity", flagName(ContextFlagInteg))
	assert.Equal(t, "Anonymous", flagName(ContextFlagAnon))
	assert.Equal(t, "Channel Bindings required/present", flagName(ContextFlagChannelBound))
	assert.Equal(t, "DCE style", flagName(ContextFlagDceStyle))
	assert.Equal(t, "Identify only", flagName(ContextFlagIdentify))
	assert.Equal(t, "Extended errors", flagName(ContextFlagExtendedError))

}

func TestFlagString(t *testing.T) {
	flags := ContextFlagConf | ContextFlagMutual | ContextFlagDeleg
	str := flags.String()

	assert.Contains(t, str, "Delegation")
	assert.Contains(t, str, "Mutual")
	assert.Contains(t, str, "Confidentiality")
	assert.NotContains(t, str, "Sequence")
}

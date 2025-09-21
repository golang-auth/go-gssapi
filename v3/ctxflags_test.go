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
	assert.Equal(t, "Delegation", FlagName(ContextFlagDeleg))
	assert.Equal(t, "Integrity", FlagName(ContextFlagInteg))
	assert.Equal(t, "Mutual authentication", FlagName(ContextFlagMutual))
	assert.Equal(t, "Channel Bindings", FlagName(ContextFlagChannelBound))
	assert.Equal(t, "Anonymous", FlagName(ContextFlagAnon))
	assert.Equal(t, "Extended errors", FlagName(ContextFlagExtendedError))
}

func TestFlagString(t *testing.T) {
	flags := ContextFlagConf | ContextFlagMutual | ContextFlagDeleg
	str := flags.String()

	assert.Contains(t, str, "Delegation")
	assert.Contains(t, str, "Mutual")
	assert.Contains(t, str, "Confidentiality")
	assert.NotContains(t, str, "Sequence")
}

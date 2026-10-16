package badversion

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompareVersion(t *testing.T) {
	t.Parallel()
	require.Equal(t, "1.3.0-beta.1", Parse("v1.3.0-beta1").String())
	require.Equal(t, "1.3-beta1", Parse("v1.3.0-beta.1").BadString())
	require.True(t, Parse("1.3.0").GreaterThan(Parse("1.3-beta1")))
	require.True(t, Parse("1.3.0").GreaterThan(Parse("1.3.0-beta1")))
	require.True(t, Parse("1.3.0-beta1").GreaterThan(Parse("1.3.0-alpha1")))
	require.True(t, Parse("1.3.1").GreaterThan(Parse("1.3.0")))
	require.True(t, Parse("1.4").GreaterThan(Parse("1.3")))
}

func TestPolarisVersion(t *testing.T) {
	t.Parallel()
	require.Equal(t, "1.15.0-polaris-alpha.12", Parse("v1.15.0-polaris-alpha.12").String())
	require.True(t, IsValid("1.15.0-polaris-alpha.12"))
	require.False(t, IsValid("1.15.0-polaris-alpha.012"))
	require.Equal(t, "1.15.0-alpha.12", Parse("1.15.0-alpha.12-deadbee").String())
	require.Equal(t, "polaris-alpha", Parse("1.15.0-polaris-alpha.12").PreReleaseIdentifier)
	require.Equal(t, 12, Parse("1.15.0-polaris-alpha.12").PreReleaseVersion)
	require.True(t, Parse("1.15.0-polaris-alpha.13").GreaterThan(Parse("1.15.0-polaris-alpha.12")))
	require.True(t, Parse("1.15.0-polaris-beta.1").GreaterThan(Parse("1.15.0-polaris-alpha.12")))
	require.True(t, Parse("1.15.0-polaris-rc.1").GreaterThan(Parse("1.15.0-polaris-beta.1")))
	require.True(t, Parse("1.15.0").GreaterThan(Parse("1.15.0-polaris-rc.1")))
}

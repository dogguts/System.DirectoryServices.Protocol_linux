// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Reflection;
using Xunit;

namespace System.DirectoryServices.Protocols.Tests
{
    public class SortRequestControlTests
    {
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        [ActiveIssue("https://github.com/dotnet/corefx/issues/21217", TargetFrameworkMonikers.UapAot)]
        public void Ctor_SortKeys(bool critical)
        {
            SortKey[] sortKeys = new SortKey[] { new SortKey("name1", "rule1", true), new SortKey("name2", "rule2", false) };
            var control = new SortRequestControl(sortKeys);
            Assert.True(control.IsCritical);
            Assert.True(control.ServerSide);
            Assert.Equal("1.2.840.113556.1.4.473", control.Type);

            Assert.NotSame(sortKeys, control.SortKeys);
            for (int i = 0; i < sortKeys.Length; i++)
            {
                Assert.Equal(sortKeys[i].AttributeName, control.SortKeys[i].AttributeName);
                Assert.Equal(sortKeys[i].MatchingRule, control.SortKeys[i].MatchingRule);
                Assert.Equal(sortKeys[i].ReverseOrder, control.SortKeys[i].ReverseOrder);
            }

            control.IsCritical = critical;
            Assert.Equal(new byte[]
            {
                0x30,0x23,0x30,0x11,0x04,0x05,0x6E,0x61,0x6D,0x65,0x31,0x80,0x05,0x72,0x75,
                0x6C,0x65,0x31,0x81,0x01,0xFF,0x30,0x0E,0x04,0x05,0x6E,0x61,0x6D,0x65,0x32,
                0x80,0x05,0x72,0x75,0x6C,0x65,0x32
            }, control.GetValue());
        }

        [Fact]
        public void Ctor_NullSortKeys_ThrowsArgumentNullException()
        {
            AssertExtensions.Throws<ArgumentNullException>("sortKeys", () => new SortRequestControl(null));
        }

        [Fact]
        public void CtorNullValueInSortKeys_ThrowsArgumentException()
        {
            AssertExtensions.Throws<ArgumentException>("sortKeys", () => new SortRequestControl(new SortKey[] { null }));
        }

        [Fact]
        public void Ctor_AttributeName_ReverseOrder()
        {
            var control = new SortRequestControl("AttributeName", true);
            SortKey sortKey = Assert.Single(control.SortKeys);
            Assert.Equal("AttributeName", sortKey.AttributeName);
            Assert.True(control.IsCritical);
            Assert.Null(sortKey.MatchingRule);
            Assert.True(sortKey.ReverseOrder);
            Assert.True(control.ServerSide);
            Assert.Equal("1.2.840.113556.1.4.473", control.Type);
        }

        [Fact]
        public void Ctor_AttributeName_MatchingRule_ReverseOrder()
        {
            var control = new SortRequestControl("AttributeName", "MatchingRule", true);
            SortKey sortKey = Assert.Single(control.SortKeys);
            Assert.Equal("AttributeName", sortKey.AttributeName);
            Assert.True(control.IsCritical);
            Assert.Equal("MatchingRule", sortKey.MatchingRule);
            Assert.True(sortKey.ReverseOrder);
            Assert.True(control.ServerSide);
            Assert.Equal("1.2.840.113556.1.4.473", control.Type);
        }

        [Fact]
        public void SortKeys_SetValid_GetReturnsExpected()
        {
            SortKey[] sortKeys = new SortKey[] { new SortKey("name1", "rule1", true), new SortKey("name2", "rule2", false) };
            var control = new SortRequestControl { SortKeys = sortKeys };
            Assert.NotSame(sortKeys, control.SortKeys);
            for (int i = 0; i < sortKeys.Length; i++)
            {
                Assert.Equal(sortKeys[i].AttributeName, control.SortKeys[i].AttributeName);
                Assert.Equal(sortKeys[i].MatchingRule, control.SortKeys[i].MatchingRule);
                Assert.Equal(sortKeys[i].ReverseOrder, control.SortKeys[i].ReverseOrder);
            }
        }

        [Fact]
        [SkipOnTargetFramework(TargetFrameworkMonikers.NetFramework, "The field _keys in full framework is called keys, so GetField returns null and ends up in a NRE")]
        public void SortKeys_GetNull_ReturnsEmptyArray()
        {
            var control = new SortRequestControl();
            FieldInfo field = control.GetType().GetField("_keys", BindingFlags.NonPublic | BindingFlags.Instance);
            field.SetValue(control, null);
            Assert.Empty(control.SortKeys);
        }

        [Fact]
        public void SortKeys_SetNull_ThrowsArgumentNullException()
        {
            var control = new SortRequestControl(new SortKey[0]);
            AssertExtensions.Throws<ArgumentNullException>("value", () => control.SortKeys = null);
        }

        [Fact]
        public void SortKeys_SetNullInValue_ThrowsArgumentException()
        {
            var control = new SortRequestControl(new SortKey[0]);
            AssertExtensions.Throws<ArgumentException>("value", () => control.SortKeys = new SortKey[] { null });
        }
    }
}

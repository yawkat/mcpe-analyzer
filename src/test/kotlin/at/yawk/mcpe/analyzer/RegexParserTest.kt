package at.yawk.mcpe.analyzer

import org.testng.Assert
import org.testng.annotations.Test

/**
 * @author yawkat
 */
class RegexParserTest {
    @Test
    fun `terminal`() = Assert.assertEquals(
            parseRegex("x"),
            RegularExpression.Terminal("x")
    )

    @Test
    fun `explicit concat`() = Assert.assertEquals(
            parseRegex("(x)"),
            RegularExpression.Concatenate(listOf(RegularExpression.Terminal("x")))
    )

    @Test
    fun `terminal concat`() = Assert.assertEquals(
            parseRegex("x y"),
            RegularExpression.Terminal("x") concat RegularExpression.Terminal("y")
    )

    @Test
    fun `terminal or`() = Assert.assertEquals(
            parseRegex("x | y"),
            RegularExpression.Terminal("x") or RegularExpression.Terminal("y")
    )

    @Test
    fun `epsilon`() = Assert.assertEquals(
            parseRegex("ε"),
            RegularExpression.empty<String>()
    )

    @Test
    fun `epsilon terminal`() = Assert.assertEquals(
            parseRegex("ε x"),
            RegularExpression.Concatenate(listOf(RegularExpression.empty<String>(), RegularExpression.Terminal("x")))
    )

    @Test
    fun `nothing`() = Assert.assertEquals(
            parseRegex("∅"),
            RegularExpression.nothing<String>()
    )

    @Test
    fun `or concat no parentheses`() = Assert.assertEquals(
            parseRegex("x y | y"),
            (RegularExpression.Terminal("x") concat RegularExpression.Terminal("y")) or RegularExpression.Terminal("y")
    )

    @Test
    fun `or concat parentheses`() = Assert.assertEquals(
            parseRegex("(x y) | y"),
            (RegularExpression.Terminal("x") concat RegularExpression.Terminal("y")) or RegularExpression.Terminal("y")
    )

    @Test
    fun `zero or more`() = Assert.assertEquals(
            parseRegex("x*"),
            RegularExpression.Terminal("x").repeat(0, null)
    )

    @Test
    fun `one or more`() = Assert.assertEquals(
            parseRegex("x+"),
            RegularExpression.Terminal("x").repeat(1, null)
    )

    @Test
    fun `zero or one`() = Assert.assertEquals(
            parseRegex("x?"),
            RegularExpression.Terminal("x").repeat(0, 1)
    )

    @Test
    fun `lower bound`() = Assert.assertEquals(
            parseRegex("x{2,}"),
            RegularExpression.Terminal("x").repeat(2, null)
    )

    @Test
    fun `double bound`() = Assert.assertEquals(
            parseRegex("x{2,5}"),
            RegularExpression.Terminal("x").repeat(2, 5)
    )

    @Test
    fun `exact bound`() = Assert.assertEquals(
            parseRegex("x{2}"),
            RegularExpression.Terminal("x").repeat(2, 2)
    )
}
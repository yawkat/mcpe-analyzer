package at.yawk.mcpe.analyzer

import org.testng.Assert
import org.testng.annotations.Test

/**
 * @author yawkat
 */
class RegexSimplifierTest {
    private fun t(int: Int) = RegularExpression.Terminal(int)

    @Test
    fun `simplify concat with repeat`() = Assert.assertEquals(
            simplify(parseRegex("x x* x")),
            parseRegex("x{2,}")
    )

    @Test
    fun `simplify simple union`() = Assert.assertEquals(
            simplify(parseRegex("x | y")),
            parseRegex("x | y")
    )

    @Test
    fun `union epsilon absorption into zeroOrMore`() = Assert.assertEquals(
            simplify(parseRegex(" | x*")),
            parseRegex("x*")
    )

    @Test
    fun `union epsilon absorption into oneOrMore`() = Assert.assertEquals(
            simplify(parseRegex(" | x+")),
            parseRegex("x*")
    )

    @Test
    fun `union repeat unification`() = Assert.assertEquals(
            simplify(parseRegex("x? | x+")),
            parseRegex("x*")
    )

    @Test
    fun `nested zeroOrMore neutralize`() =Assert.assertEquals(
            simplify(parseRegex("x**")),
            parseRegex("x*")
    )

    @Test
    fun `nested zeroOrMore + oneOrMore neutralize`() = Assert.assertEquals(
            simplify(parseRegex("x+*")),
            parseRegex("x*")
    )

    @Test
    fun `nested constant neutralize`() = Assert.assertEquals(
            simplify(parseRegex("x{4}{5}")),
            parseRegex("x{20}")
    )

    @Test
    fun `union extract prefix from concat`() = Assert.assertEquals(
            simplify(parseRegex("x y | x z")),
            parseRegex("x (y | z)")
    )

    @Test
    fun `union extract suffix from concat`() = Assert.assertEquals(
            simplify(parseRegex("x z | y z")),
            parseRegex("(x | y) z")
    )

    @Test
    fun `union extract single prefix from twoOrMore`() = Assert.assertEquals(
            simplify(parseRegex("x{2,} y | x z")),
            parseRegex("x (x+ y | z)")
    )

    @Test
    fun `epsilon union to optional`() = Assert.assertEquals(
            simplify(parseRegex("|x")),
            parseRegex("x?")
    )

    @Test
    fun `x+ x+ → x{2,}`() = Assert.assertEquals(
            simplify(parseRegex("x+ x+")),
            parseRegex("x{2,}")
    )

    @Test
    fun `list flatten after member simplification`() = Assert.assertEquals(
            simplify(parseRegex("x (y z){1}")),
            parseRegex("x y z")
    )

    @Test
    fun `or flatten after member simplification`() = Assert.assertEquals(
            simplify(parseRegex("x | (y | z){1}")),
            parseRegex("x | y | z")
    )

    @Test
    fun `absorb concat into repeat right`() = Assert.assertEquals(
            simplify(parseRegex("(x y)* x y")),
            parseRegex("(x y)+")
    )

    @Test
    fun `absorb concat into repeat left`() = Assert.assertEquals(
            simplify(parseRegex("x y (x y)*")),
            parseRegex("(x y)+")
    )

    //@Test todo: would be nice if this passed
    fun `union 1`() = Assert.assertEquals(
            simplify((t(1) concat t(2)) or (t(1).repeat(0, 1) concat t(2) concat t(1)) or t(2)),
            t(1).repeat(0, 1) concat t(2) concat t(1).repeat(0, 1)
    )

    //@Test
    fun `simplify complex`() {
        println( (((t(1) concat t(2) concat t(3) concat t(3).zeroOrMore() concat t(2)) or (t(1) concat t(2) concat t(2))) concat t(4).zeroOrMore() concat t(4)) or (t(1) concat t(2) concat t(3) concat t(3).zeroOrMore() concat t(2)) or (t(1) concat t(2) concat t(2)))
        Assert.assertEquals(
                simplify(
                        ((((t(1) concat t(2) concat t(3) concat t(3).zeroOrMore() concat t(2)) or (t(1) concat t(2) concat t(2))) concat t(4).zeroOrMore() concat t(4)) or (t(1) concat t(2) concat t(3) concat t(3).zeroOrMore() concat t(2)) or (t(1) concat t(2) concat t(2)))),
                null
        )
    }
}
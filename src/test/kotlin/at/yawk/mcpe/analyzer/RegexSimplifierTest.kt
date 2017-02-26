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
            simplify(t(1) concat t(1).zeroOrMore() concat t(1)),
            RegularExpression.Repeat(t(1), 2, null)
    )

    @Test
    fun `simplify simple union`() = Assert.assertEquals(
            simplify(t(1) or t(2)),
            t(1) or t(2)
    )

    @Test
    fun `union epsilon absorption into zeroOrMore`() = Assert.assertEquals(
            simplify(RegularExpression.empty<Int>() or t(0).zeroOrMore()),
            t(0).zeroOrMore()
    )

    @Test
    fun `union epsilon absorption into oneOrMore`() = Assert.assertEquals(
            simplify(RegularExpression.empty<Int>() or (t(0).zeroOrMore() concat t(0))),
            t(0).zeroOrMore()
    )

    @Test
    fun `nested zeroOrMore neutralize`() = Assert.assertEquals(
            simplify(RegularExpression.Repeat(RegularExpression.Repeat(t(0), 0, null), 0, null)),
            t(0).zeroOrMore()
    )

    @Test
    fun `nested zeroOrMore + oneOrMore neutralize`() = Assert.assertEquals(
            simplify(RegularExpression.Repeat(RegularExpression.Repeat(t(0), 1, null), 0, null)),
            t(0).zeroOrMore()
    )

    @Test
    fun `nested constant neutralize`() = Assert.assertEquals(
            simplify(RegularExpression.Repeat(RegularExpression.Repeat(t(0), 5, 5), 4, 4)),
            RegularExpression.Repeat(t(0), 20, 20)
    )

    @Test
    fun `union extract prefix from concat`() = Assert.assertEquals(
            simplify((t(0) concat t(1)) or (t(0) concat t(2))),
            t(0) concat (t(1) or t(2))
    )

    @Test
    fun `union extract suffix from concat`() = Assert.assertEquals(
            simplify((t(0) concat t(2)) or (t(1) concat t(2))),
            (t(0) or t(1)) concat t(2)
    )

    @Test
    fun `union extract single prefix from twoOrMore`() = Assert.assertEquals(
            simplify((t(1).repeat(2, null) concat t(2)) or (t(1) concat t(3))),
            t(1) concat ((t(1).repeat(1, null) concat t(2)) or t(3))
    )

    @Test
    fun `epsilon union to optional`() = Assert.assertEquals(
            simplify(RegularExpression.empty<Int>() or t(1)),
            t(1).repeat(0,1)
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
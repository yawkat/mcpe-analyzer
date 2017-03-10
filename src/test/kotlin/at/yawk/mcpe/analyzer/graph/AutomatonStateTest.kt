package at.yawk.mcpe.analyzer.graph

import at.yawk.mcpe.analyzer.parseRegex
import at.yawk.mcpe.analyzer.simplify
import org.testng.Assert
import org.testng.annotations.Test

/**
 * @author yawkat
 */
class AutomatonStateTest {
    private fun testToRegex(expected: String, start: Int, f: AutomatonState.Companion.FluentBuilder<Int, String>.() -> Unit) {
        val expectedRegex = parseRegex(expected)
        val automaton = AutomatonState.build(start, f)
        val regex = automaton.destructiveToRegex()
        Assert.assertEquals(simplify(regex), expectedRegex)
    }

    @Test
    fun `simple transition`() = testToRegex("term", 1) {
        1 on "term" goto 2
        accept(2)
    }

    @Test
    fun `single state, repeat term`() = testToRegex("term*", 1) {
        1 on "term" goto 1
        accept(1)
    }

    @Test
    fun `single state, no transition`() = testToRegex("", 1) {
        accept(1)
    }

    @Test
    fun `two states, repeat term`() = testToRegex("term+", 1) {
        1 on "term" goto 1
        1 on "term" goto 2
        accept(2)
    }

    @Test
    fun `two alternative paths`() = testToRegex("a|b", 1) {
        1 on "a" goto 2
        1 on "b" goto 3
        accept(2)
        accept(3)
    }

    @Test
    fun `concat`() = testToRegex("a b", 1) {
        1 on "a" goto 2
        2 on "b" goto 3
        accept(3)
    }

    @Test
    fun `circle`() = testToRegex("(a b c)* a", 1) {
        1 on "a" goto 2
        2 on "b" goto 3
        3 on "c" goto 1
        accept(2)
    }
}
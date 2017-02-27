package at.yawk.mcpe.analyzer

import java.util.ArrayList
import java.util.HashSet
import java.util.regex.Pattern

/**
 * @author yawkat
 */
fun parseRegex(input: String, terminalPattern: Pattern = Pattern.compile("\\w+")) = object : RegexParser<String>(input) {
    val matcher = terminalPattern.matcher(input)

    override fun takeTerminal(): RegularExpression.Terminal<String>? {
        if (matcher.find(i) && matcher.start() == i) {
            i = matcher.end()
            return RegularExpression.Terminal(matcher.group())
        } else {
            return null
        }
    }
}.parse()

class ParseException(msg: String) : Exception(msg)

private abstract class RegexParser<out T>(val input: String) {
    var i = 0

    fun hasRemaining() = i < input.length
    fun peek() = input[i]
    fun take() = input[i++]

    inline fun take(predicate: (Char) -> Boolean): String {
        val start = i
        while (hasRemaining() && predicate(peek())) take()
        return input.substring(start, i)
    }

    private fun skipWhitespace() {
        while (hasRemaining() && peek().isWhitespace()) take()
    }

    abstract fun takeTerminal(): RegularExpression.Terminal<T>?

    private fun unexpectedToken(token: String): Nothing = throw ParseException("Unexpected token '$token' near index $i")

    fun parse(inParentheses: Boolean = false): RegularExpression<T> {
        val or = ArrayList<List<RegularExpression<T>>>()
        var concat = ArrayList<RegularExpression<T>>()
        or.add(concat)

        outer@ while (true) {
            skipWhitespace()
            if (!hasRemaining()) {
                break
            }
            val terminal = takeTerminal()
            if (terminal != null) {
                concat.add(terminal)
                continue
            }
            when (take()) {
                '(' -> concat.add(parse(inParentheses = true))
                ')' ->
                    if (inParentheses) break@outer
                    else unexpectedToken(")")
                '|' -> {
                    concat = ArrayList()
                    or.add(concat)
                }
                '?' -> {
                    if (concat.isEmpty()) unexpectedToken("?")
                    concat[concat.size - 1] = concat.last().repeat(0, 1)
                }
                '*' -> {
                    if (concat.isEmpty()) unexpectedToken("*")
                    concat[concat.size - 1] = concat.last().repeat(0, null)
                }
                '+' -> {
                    if (concat.isEmpty()) unexpectedToken("+")
                    concat[concat.size - 1] = concat.last().repeat(1, null)
                }
                '{' -> {
                    if (concat.isEmpty()) unexpectedToken("{")
                    skipWhitespace()
                    val min = take(Char::isDigit).toInt()
                    skipWhitespace()
                    val max: Int?
                    if (peek() == ',') {
                        take()
                        skipWhitespace()
                        val maxStr = take(Char::isDigit)
                        max = if (maxStr.isEmpty()) null else maxStr.toInt()
                        skipWhitespace()
                    } else {
                        max = min
                    }
                    if (take() != '}') throw ParseException("Expected '}' near index $i")
                    concat[concat.size - 1] = concat.last().repeat(min, max)
                }
                'ε' -> concat.add(RegularExpression.empty())
                '∅' -> concat.add(RegularExpression.nothing())
                else -> throw ParseException("Unexpected token near index $i")
            }
        }
        if (or.size == 1) {
            if (concat.size == 1 && !inParentheses) {
                return concat[0]
            } else {
                return RegularExpression.Concatenate(concat)
            }
        } else {
            return RegularExpression.Or(or.mapTo(HashSet()) {
                if (it.size == 1) {
                    it[0]
                } else {
                    RegularExpression.Concatenate(it)
                }
            })
        }
    }
}
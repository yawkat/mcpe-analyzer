package at.yawk.mcpe.analyzer

import java.util.ArrayList
import java.util.HashSet

/**
 * @author yawkat
 */
interface RegularExpression<out T> {
    @Suppress("UNCHECKED_CAST")
    companion object {
        private val _empty = Concatenate<Any>(emptyList())
        private val _nothing = Or<Any>(emptySet())
        fun <T> empty(): RegularExpression<T> = _empty as RegularExpression<T>
        fun <T> nothing(): RegularExpression<T> = _nothing as RegularExpression<T>
    }

    fun <R> map(leafMapper: (T) -> RegularExpression<R>): RegularExpression<R>

    data class Terminal<out T>(val value: T) : RegularExpression<T> {
        override fun toString() = value.toString()
        override fun <R> map(leafMapper: (T) -> RegularExpression<R>) = leafMapper(value)
    }

    data class Concatenate<out T>(val members: List<RegularExpression<T>>) : RegularExpression<T> {
        override fun toString() =
                if (members.isEmpty()) "ε"
                else members.joinToString(prefix = "(", separator = " ", postfix = ")")

        override fun <R> map(leafMapper: (T) -> RegularExpression<R>) = Concatenate(members.map { it.map(leafMapper) })
    }

    data class Or<out T>(val alternatives: Set<RegularExpression<T>>) : RegularExpression<T> {
        override fun toString() =
                if (alternatives.isEmpty()) "∅"
                else alternatives.joinToString(prefix = "(", separator = "|", postfix = ")")

        override fun <R> map(leafMapper: (T) -> RegularExpression<R>) = Or<R>(alternatives.mapTo(HashSet()) { it.map(leafMapper) })
    }

    data class Repeat<out T>(val expression: RegularExpression<T>, val min: Int, val max: Int?) : RegularExpression<T> {
        init {
            if (max != null && max < min) throw IllegalArgumentException("max=$max < min=$min")
            if (min < 0) throw IllegalArgumentException("min=$min < 0")
        }

        val suffix: String
            get() = when {
                min == max -> "{$min}"
                min == 0 && max == null -> "*"
                min == 1 && max == null -> "+"
                max == null -> "{$min,}"
                min == 0 && max == 1 -> "?"
                else -> "{$min,$max}"
            }

        override fun toString() = "$expression$suffix"

        override fun <R> map(leafMapper: (T) -> RegularExpression<R>) = Repeat(expression.map(leafMapper), min, max)
    }
}

@Suppress("IfThenToElvis")
private inline fun <T, COLLECTION : MutableCollection<RegularExpression<T>>, reified COMPOSITE : RegularExpression<T>> join(
        left: RegularExpression<T>,
        right: RegularExpression<T>,

        GET_COMPONENTS: COMPOSITE.() -> Collection<RegularExpression<T>>,
        MAKE_COLLECTION: (Int) -> COLLECTION,
        MAKE_COMPOSITE: (COLLECTION) -> COMPOSITE
): RegularExpression<T> {
    var size = 0
    size += if (left is COMPOSITE) left.GET_COMPONENTS().size else 1
    size += if (right is COMPOSITE) right.GET_COMPONENTS().size else 1
    val joined = MAKE_COLLECTION(size)
    if (left is COMPOSITE) joined.addAll(left.GET_COMPONENTS()) else joined.add(left)
    if (right is COMPOSITE) joined.addAll(right.GET_COMPONENTS()) else joined.add(right)
    if (joined.size == 1) {
        return joined.single()
    } else {
        return MAKE_COMPOSITE(joined)
    }
}

infix fun <T> RegularExpression<T>.or(right: RegularExpression<T>): RegularExpression<T> = join(
        this, right,
        GET_COMPONENTS = { alternatives },
        MAKE_COLLECTION = { HashSet<RegularExpression<T>>(it) },
        MAKE_COMPOSITE = { RegularExpression.Or(it) }
)

infix fun <T> RegularExpression<T>.concat(right: RegularExpression<T>): RegularExpression<T> = join(
        this, right,
        GET_COMPONENTS = { members },
        MAKE_COLLECTION = { ArrayList<RegularExpression<T>>(it) },
        MAKE_COMPOSITE = { RegularExpression.Concatenate(it) }
)

fun <T> RegularExpression<T>.zeroOrMore(): RegularExpression.Repeat<T> =
        if (this is RegularExpression.Repeat && this.min == 0 && this.max == null) this
        else RegularExpression.Repeat(this, 0, null)

fun <T> RegularExpression<T>.repeat(min: Int, max: Int?): RegularExpression.Repeat<T> =
        RegularExpression.Repeat(this, min, max)
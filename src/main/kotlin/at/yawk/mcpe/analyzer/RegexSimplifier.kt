package at.yawk.mcpe.analyzer

import org.slf4j.LoggerFactory
import java.util.ArrayDeque
import java.util.ArrayList
import java.util.HashSet

/**
 * @author yawkat
 */
private val log = LoggerFactory.getLogger("at.yawk.mcpe.analyzer.RegexSimplifier")

private fun <T> List<T>.replaced(index: Int, value: T): List<T> {
    val result = ArrayList<T>(size)
    result.addAll(subList(0, index))
    result.add(value)
    result.addAll(subList(index + 1, size))
    return result
}

fun <T> simplify(regex: RegularExpression<T>): RegularExpression<T> =
        RegexSimplifier<T>().simplify(regex)

private class RegexSimplifier<T> {
    private var depth: Int = 0

    private fun trace(s: String) {
        log.trace("  ".repeat(depth) + s)
    }

    private inline fun trace(s: () -> String) {
        if (log.isTraceEnabled) trace(s())
    }

    private inline fun <R> trace(s: () -> String, block: () -> R): R {
        trace(s)
        depth++
        try {
            return block()
        } finally {
            depth--
        }
    }

    private inline fun <R> traceAfter(s: (R) -> String, block: () -> R): R {
        depth++
        try {
            val v = block()
            trace(s(v))
            return v
        } finally {
            depth--
        }
    }

    private inner class ConcatBuilder {
        val items = ArrayList<RegularExpression<T>>()

        private fun insertionString(tail: Boolean, toInsert: Any) =
                if (tail) "$items <- $toInsert"
                else "$toInsert -> $items"

        fun add(ex: RegularExpression<T>, tail: Boolean = true) {
            if (ex is RegularExpression.Concatenate) {
                trace({ "${insertionString(tail, ex.members)} flatten before simplify" }) {
                    ex.members.forEach { add(it, tail) }
                }
                return
            }
            val here = simplify(ex)
            if (here is RegularExpression.Concatenate) {
                trace({ "${insertionString(tail, here.members)} flatten after simplify" }) {
                    here.members.forEach { add(it, tail) }
                }
                return
            }

            trace({ insertionString(tail, here) }) {
                if (tail) {
                    items.add(here)
                    while (items.size >= 2 && tryMergeIndices(items.size - 2, items.size - 1)) {
                    }
                } else {
                    items.add(0, here)
                    while (items.size >= 2 && tryMergeIndices(0, 1)) {
                    }
                }
            }
        }

        fun tryMergeIndices(left: Int, right: Int): Boolean {
            val merged = tryMerge(items[left], items[right])
            if (merged != null) {
                items[left] = merged
                items.removeAt(right)
                return true
            } else {
                return false
            }
        }

        private fun tryMergeSymmetrical(left: RegularExpression<T>, right: RegularExpression<T>): RegularExpression.Repeat<T>? {
            if (left is RegularExpression.Repeat) {
                if (left.expression == right) {
                    val result = left.copy(min = left.min + 1, max = left.max?.plus(1))
                    trace { "merge '$left' <- '$right' (right is left's expression) = $result" }
                    return result
                } else if (right is RegularExpression.Repeat && right.expression == left.expression) {
                    val max = if (left.max == null || right.max == null) null else left.max + right.max
                    val result = left.copy(min = left.min + right.min, max = max)
                    trace { "merge '$left' <- '$right' (right == left) = $result" }
                    return result
                }
            }
            return null
        }

        private fun tryMerge(left: RegularExpression<T>, right: RegularExpression<T>): RegularExpression.Repeat<T>? {
            trace { "tryMerge $left <-> $right" }
            tryMergeSymmetrical(left, right)?.let { return it }
            tryMergeSymmetrical(right, left)?.let { return it }
            if (left == right) {
                trace { "merge '$left' + '$right' (identical to repetition)" }
                return left.repeat(2, 2)
            }
            return null
        }

        fun build(): RegularExpression<T> = when (items.size) {
            0 -> RegularExpression.empty()
            1 -> {
                trace { "Unwrap single expression $items" }
                items.single()
            }
            else -> RegularExpression.Concatenate(items)
        }
    }

    private inner class OrBuilder {
        val items = HashSet<RegularExpression<T>>()

        fun add(ex: RegularExpression<T>) {
            if (ex is RegularExpression.Or) {
                trace({ "$items <- ${ex.alternatives} flatten before simplify" }) {
                    ex.alternatives.forEach { add(it) }
                }
                return
            }
            val here = simplify(ex)
            if (here is RegularExpression.Or) {
                trace({ "$items <- ${here.alternatives} flatten before simplify" }) {
                    here.alternatives.forEach { add(it) }
                }
                return
            }

            trace({ "$items <- $here" })
            items.add(here)
        }

        fun build(): RegularExpression<T> {
            if (items.size == 1) return items.single()
            val prefix = traceAfter({ "$items extracted prefix $it" }) {
                extractPrefixSuffix(prefix = true)
            }
            val suffix = traceAfter({ "$items extracted suffix $it" }) {
                extractPrefixSuffix(prefix = false)
            }

            val mergeQueue = ArrayDeque<Pair<RegularExpression<T>, RegularExpression<T>>>()
            for ((ai, a) in items.withIndex()) {
                @Suppress("LoopToCallChain")
                for ((bi, b) in items.withIndex()) {
                    if (bi > ai) {
                        mergeQueue.push(a to b)
                    }
                }
            }
            while (true) {
                val (a, b) = mergeQueue.poll() ?: break
                val merged = tryMerge(a, b) ?: continue
                trace { "UnionMerged $a <-> $b = $merged" }
                items.remove(a)
                items.remove(b)
                mergeQueue.removeAll { it.first === a || it.second === a || it.first === b || it.second === b }
                items.mapTo(mergeQueue) { it to merged }
                items.add(merged)
            }

            // ε|x -> x?
            if (items.size == 2 && items.remove(RegularExpression.empty())) {
                trace { "Simplify $items to optional" }
                val remaining = items.single()
                items.clear()
                items.add(remaining.repeat(0, 1))
            }

            if (prefix == RegularExpression.empty<T>() && suffix == RegularExpression.empty<T>()) {
                return when (items.size) {
                    0 -> RegularExpression.nothing()
                    1 -> {
                        trace { "Unwrap single expression $items" }
                        items.single()
                    }
                    else -> RegularExpression.Or(items)
                }
            } else {
                return when (items.size) {
                    0 -> RegularExpression.nothing()
                    1 -> {
                        trace({ "simplify '$prefix' + $items unwrapped + '$suffix'" }) {
                            simplify(prefix concat items.single() concat suffix)
                        }
                    }
                    else -> {
                        trace { "'$prefix' + $items + '$suffix'" }
                        prefix concat RegularExpression.Or(items) concat suffix
                    }
                }
            }
        }

        private fun RegularExpression<T>.matchesEpsilon(): Boolean = when (this) {
            is RegularExpression.Terminal -> false
            is RegularExpression.Concatenate -> members.all { it.matchesEpsilon() }
            is RegularExpression.Or -> alternatives.any { it.matchesEpsilon() }
            is RegularExpression.Repeat -> min == 0 || expression.matchesEpsilon()
            else -> throw AssertionError()
        }

        /**
         * Try to merge [left] and [right] into `return` so that [left] | [right] = return and
         * prefix? [left] suffix? | [right] = prefix? `return` suffix?
         */
        private fun tryMergeUnidirectional(left: RegularExpression<T>, right: RegularExpression<T>): RegularExpression<T>? {
            if (left == right) return left
            if (right == RegularExpression.empty<T>()) {
                if (left.matchesEpsilon()) {
                    trace { "Absorbing epsilon into expression $left without change" }
                    return left
                }
                if (left is RegularExpression.Repeat && left.min == 1) {
                    trace { "Absorbing epsilon into expression $left by + -> *" }
                    return left.copy(min = 0)
                }
                trace { "Absorbing epsilon into expression $left by making it optional" }
                return simplify(left.repeat(0, 1))
            }
            if (left is RegularExpression.Concatenate) {
                val leftNonEmpty = left.members.withIndex().filter { !it.value.matchesEpsilon() }
                if (leftNonEmpty.size == 1) {
                    val toMerge = leftNonEmpty.single()
                    trace({ "Attempting to merge $right into single non-empty item of ${left.members}" }) {
                        tryMergeUnidirectional(toMerge.value, right)?.let { mergedMember ->
                            return left.copy(members = left.members.replaced(toMerge.index, mergedMember))
                        }
                    }
                }
                if (leftNonEmpty.size == 2) {
                    val (a, b) = leftNonEmpty
                    if (b.value == right) {
                        trace({ "Trying to merge $right into $left by making $a optional" }) {
                            val aEpsilon = tryMerge(a.value, RegularExpression.empty())
                            if (aEpsilon != null) {
                                trace { "Merged $right into $left by making $a optional" }
                                return left.copy(members = left.members
                                        .replaced(a.index, aEpsilon))
                            }
                        }
                    }
                    if (a.value == right) {
                        trace({ "Trying to merge $right into $left by making $b optional" }) {
                            val bEpsilon = tryMerge(b.value, RegularExpression.empty())
                            if (bEpsilon != null) {
                                return left.copy(members = left.members
                                        .replaced(b.index, bEpsilon))
                            }
                        }
                    }
                }
                if (right is RegularExpression.Concatenate) {
                    if (leftNonEmpty.map { it.value } == right.members) {
                        trace { "${left.members} absorbed ${right.members} because the latter is a strict subset" }
                        return left
                    }
                    if (leftNonEmpty.size == right.members.size + 1) {
                        var candidate: IndexedValue<RegularExpression<T>>? = null
                        var possible = true
                        for (i in right.members.indices) {
                            if (candidate == null) {
                                if (leftNonEmpty[i].value == right.members[i]) continue
                                candidate = leftNonEmpty[i]
                            }
                            if (leftNonEmpty[i + 1].value != right.members[i]) {
                                possible = false
                                break
                            }
                        }
                        if (possible) {
                            if (candidate == null) candidate = leftNonEmpty.last()
                            trace { "${left.members} absorbed ${right.members} by making $candidate optional" }
                            return left.copy(left.members.replaced(candidate.index, simplify(candidate.value.repeat(0, 1))))
                        }
                    }
                }
            }
            if (left is RegularExpression.Repeat) {
                if (left.expression == right) {
                    if (left.min == 2) {
                        trace { "$left <- $right by changing to *" }
                        return left.copy(min = 1)
                    }
                    if (left.min <= 1) {
                        trace { "$left <- $right because it is a strict subset" }
                        return left
                    }
                }

                if (right is RegularExpression.Repeat && left.expression == right.expression) {
                    if (left.min <= right.min) {
                        // x{m,n} | x{n+1,o} -> x{m,o}
                        if (left.max == null || left.max + 1 >= right.min) {
                            val max = if (left.max == null || right.max == null) null
                            else Math.max(left.max, right.max)
                            return left.copy(max = max)
                        }
                    }
                }
            }
            return null
        }

        private fun tryMerge(a: RegularExpression<T>, b: RegularExpression<T>): RegularExpression<T>? {
            tryMergeUnidirectional(a, b)?.let { return it }
            tryMergeUnidirectional(b, a)?.let { return it }
            return null
        }

        private fun selectStartPrefixSuffix(firstItem: RegularExpression<T>, prefix: Boolean): Pair<RegularExpression<T>, RegularExpression<T>>? {
            when (firstItem) {
                is RegularExpression.Concatenate -> {
                    val members = firstItem.members
                    return if (members.isEmpty()) null
                    else {
                        val (head, tail) = selectStartPrefixSuffix(if (prefix) members.first() else members.last(), prefix) ?: return null
                        val ourTail =
                                if (prefix) tail concat RegularExpression.Concatenate(members.drop(1))
                                else RegularExpression.Concatenate(members.dropLast(1)) concat tail
                        return Pair(head, ourTail)
                    }
                }
                else -> return Pair(firstItem, RegularExpression.empty())
            }
        }

        private fun extractPrefixSuffix(prefix: Boolean): RegularExpression<T> {
            val name = if (prefix) "prefix" else "suffix"

            fun directionalConcat(r1: RegularExpression<T>, r2: RegularExpression<T>) =
                    if (prefix) r1 concat r2
                    else r2 concat r1

            val fixBuilder = ConcatBuilder()
            passes@ while (true) {
                val itemIterator = items.iterator()
                if (!itemIterator.hasNext()) break
                var newItems = HashSet<RegularExpression<T>>()
                var (suggestedPrefix, firstTail) = selectStartPrefixSuffix(itemIterator.next(), prefix) ?: break
                trace { "PASS | Suggested $name is $suggestedPrefix (with first tail $firstTail)" }
                newItems.add(firstTail)

                fun popPrefix(ex: RegularExpression<T>): RegularExpression<T>? {
                    val suggestedPrefixLocal = suggestedPrefix
                    when {
                        ex == suggestedPrefixLocal -> {
                            trace { "Perfect $name match" }
                            return RegularExpression.empty()
                        }
                        ex is RegularExpression.Repeat && ex.min > 0 -> {
                            trace({ "Enter repeat expression $ex for $name" }) {
                                return popPrefix(ex.expression)?.let {
                                    directionalConcat(it, ex.copy(min = ex.min - 1))
                                }
                            }
                        }
                        ex is RegularExpression.Concatenate -> {
                            return if (ex.members.isEmpty()) null
                            else trace({ "Enter concat expression $ex for $name" }) {
                                popPrefix(if (prefix) ex.members.first() else ex.members.last())?.let {
                                    directionalConcat(it, RegularExpression.Concatenate(if (prefix) ex.members.drop(1) else ex.members.dropLast(1)))
                                }
                            }
                        }
                        suggestedPrefixLocal is RegularExpression.Repeat && suggestedPrefixLocal.min > 0
                                && suggestedPrefixLocal.expression == ex -> {
                            val moveToMembers = suggestedPrefixLocal.copy(min = suggestedPrefixLocal.min - 1)
                            newItems = newItems.mapTo(HashSet()) { directionalConcat(moveToMembers, it) }
                            trace { "Reducing $name to $ex to accommodate $ex, new items are $newItems" }
                            suggestedPrefix = ex
                            return RegularExpression.empty()
                        }
                        else -> return null
                    }
                }

                while (itemIterator.hasNext()) {
                    val item = itemIterator.next()
                    val popped = popPrefix(item) ?: break@passes
                    newItems.add(popped)
                }
                fixBuilder.add(suggestedPrefix, tail = prefix)
                items.clear()
                newItems.forEach { add(it) }
            }
            return fixBuilder.build()
        }
    }

    fun simplify(regex: RegularExpression<T>): RegularExpression<T> = trace({ "Simplifying $regex" }) {
        when (regex) {
            is RegularExpression.Terminal -> return regex
            is RegularExpression.Concatenate -> {
                val builder = ConcatBuilder()
                builder.add(regex)
                return builder.build()
            }
            is RegularExpression.Or -> {
                val builder = OrBuilder()
                builder.add(regex)
                return builder.build()
            }
            is RegularExpression.Repeat -> {
                if (regex.max == 0) {
                    trace { "<any>{0} -> ${RegularExpression.empty<T>()}" }
                    return RegularExpression.empty()
                }
                val simple = simplify(regex.expression)
                if (regex.min == 1 && regex.max == 1) {
                    trace { "Unwrapping single repetition to $simple" }
                    return simple
                }
                if (simple == RegularExpression.empty<T>()) {
                    trace { "Unwrapping repetition of ${RegularExpression.empty<T>()}" }
                    return simple
                }
                if (simple == RegularExpression.nothing<T>()) {
                    if (regex.min == 0) {
                        trace { "Unwrapping repetition of ${RegularExpression.nothing<T>()} to ${RegularExpression.empty<T>()}" }
                        return RegularExpression.empty<T>()
                    } else {
                        trace { "Unwrapping repetition of ${RegularExpression.nothing<T>()}" }
                        return RegularExpression.nothing<T>()
                    }
                }
                if (simple is RegularExpression.Repeat) {
                    val min1 = regex.min
                    val min2 = simple.min
                    val max1 = regex.max
                    val max2 = simple.max
                    if (min1 <= 1 && min2 <= 1 && (max1 == null || max2 == null)) {
                        trace { "Combining nested repetitions with minimum $min1, $min2" }
                        return RegularExpression.Repeat(simple.expression, min1 * min2, null)
                    }
                    if (min1 == max1 && min2 == max2) {
                        trace { "Combining constant nested repetitions with counts $min1, $min2" }
                        return RegularExpression.Repeat(simple.expression, min1 * min2, min1 * min2)
                    }
                }
                return regex.copy(expression = simple)
            }
            else -> throw AssertionError()
        }
    }
}
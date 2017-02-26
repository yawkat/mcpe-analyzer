package at.yawk.mcpe.analyzer

import java.util.ArrayDeque
import java.util.ArrayList
import java.util.HashSet

/**
 * @author yawkat
 */
private fun <T> List<T>.replaced(index: Int, value: T): List<T> {
    val result = ArrayList<T>(size)
    result.addAll(subList(0, index))
    result.add(value)
    result.addAll(subList(index + 1, size))
    return result
}

private class ConcatBuilder<T> {
    val items = ArrayList<RegularExpression<T>>()

    fun add(ex: RegularExpression<T>, tail: Boolean = true) {
        if (ex is RegularExpression.Concatenate) {
            ex.members.forEach { add(it, tail) }
            return
        }
        val here = simplify(ex)
        if (here is RegularExpression.Concatenate) {
            here.members.forEach { add(it, tail) }
            return
        }

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
                return left.copy(min = left.min + 1, max = left.max?.plus(1))
            } else if (right is RegularExpression.Repeat && right.expression == left.expression) {
                val max = if (left.max == null || right.max == null) null else left.max + right.max
                return left.copy(min = left.min + right.min, max = max)
            }
        }
        return null
    }

    private fun tryMerge(left: RegularExpression<T>, right: RegularExpression<T>): RegularExpression.Repeat<T>? {
        tryMergeSymmetrical(left, right)?.let { return it }
        tryMergeSymmetrical(right, left)?.let { return it }
        if (left == right) return left.repeat(2, 2)
        return null
    }

    fun build(): RegularExpression<T> = when (items.size) {
        0 -> RegularExpression.empty()
        1 -> items.single()
        else -> RegularExpression.Concatenate(items)
    }
}

private class OrBuilder<T> {
    val items = HashSet<RegularExpression<T>>()

    fun add(ex: RegularExpression<T>) {
        if (ex is RegularExpression.Or) {
            ex.alternatives.forEach { add(it) }
            return
        }
        val here = simplify(ex)
        if (here is RegularExpression.Or) {
            here.alternatives.forEach { add(it) }
            return
        }

        items.add(here)
    }

    fun build(): RegularExpression<T> {
        if (items.size == 1) return items.single()
        val prefix = extractPrefixSuffix(prefix = true)
        val suffix = extractPrefixSuffix(prefix = false)

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
            items.remove(a)
            items.remove(b)
            mergeQueue.removeAll { it.first === a || it.second === a || it.first === b || it.second === b }
            items.mapTo(mergeQueue) { it to merged }
            items.add(merged)
        }

        // ε|x -> x?
        if (items.size == 2 && items.remove(RegularExpression.empty())) {
            val remaining = items.single()
            items.clear()
            items.add(remaining.repeat(0, 1))
        }

        if (prefix == RegularExpression.empty<T>() && suffix == RegularExpression.empty<T>()) {
            return when (items.size) {
                0 -> RegularExpression.nothing()
                1 -> items.single()
                else -> RegularExpression.Or(items)
            }
        } else {
            return when (items.size) {
                0 -> RegularExpression.nothing()
                1 -> simplify(prefix concat items.single() concat suffix)
                else -> prefix concat RegularExpression.Or(items) concat suffix
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

    private fun tryMergeUnidirectional(left: RegularExpression<T>, right: RegularExpression<T>): RegularExpression<T>? {
        if (left == right) return left
        if (right == RegularExpression.empty<T>()) {
            if (left.matchesEpsilon()) return left
            if (left is RegularExpression.Repeat && left.min == 1) return left.copy(min = 0)
            return simplify(left.repeat(0, 1))
        }
        if (left is RegularExpression.Concatenate) {
            val leftNonEmpty = left.members.withIndex().filter { !it.value.matchesEpsilon() }
            if (leftNonEmpty.size == 1) {
                val toMerge = leftNonEmpty.single()
                tryMergeUnidirectional(toMerge.value, right)?.let { mergedMember ->
                    return left.copy(members = left.members.replaced(toMerge.index, mergedMember))
                }
            }
            if (leftNonEmpty.size == 2) {
                val (a, b) = leftNonEmpty
                if (b.value == right) {
                    val aEpsilon = tryMerge(a.value, RegularExpression.empty())
                    if (aEpsilon != null) {
                        return left.copy(members = left.members
                                .replaced(a.index, aEpsilon))
                    }
                }
                if (a.value == right) {
                    val bEpsilon = tryMerge(b.value, RegularExpression.empty())
                    if (bEpsilon != null) {
                        return left.copy(members = left.members
                                .replaced(b.index, bEpsilon))
                    }
                }
            }
            if (right is RegularExpression.Concatenate) {
                if (leftNonEmpty.map { it.value } == right.members) return left
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
                        return left.copy(left.members.replaced(candidate.index, simplify(candidate.value.repeat(0, 1))))
                    }
                }
            }
        }
        if (left is RegularExpression.Repeat && left.expression == right) {
            if (left.min == 2) return left.copy(min = 1)
            if (left.min <= 1) return left
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
        fun directionalConcat(r1: RegularExpression<T>, r2: RegularExpression<T>) =
                if (prefix) r1 concat r2
                else r2 concat r1

        val fixBuilder = ConcatBuilder<T>()
        passes@ while (true) {
            val itemIterator = items.iterator()
            if (!itemIterator.hasNext()) break
            var newItems = HashSet<RegularExpression<T>>()
            var (suggestedPrefix, firstTail) = selectStartPrefixSuffix(itemIterator.next(), prefix) ?: break
            newItems.add(firstTail)

            fun popPrefix(ex: RegularExpression<T>): RegularExpression<T>? {
                val suggestedPrefixLocal = suggestedPrefix
                when {
                    ex == suggestedPrefixLocal -> return RegularExpression.empty()
                    ex is RegularExpression.Repeat && ex.min > 0 ->
                        return popPrefix(ex.expression)?.let {
                            directionalConcat(it, ex.copy(min = ex.min - 1))
                        }
                    ex is RegularExpression.Concatenate -> {
                        return if (ex.members.isEmpty()) null
                        else popPrefix(if (prefix) ex.members.first() else ex.members.last())?.let {
                            directionalConcat(it, RegularExpression.Concatenate(if (prefix) ex.members.drop(1) else ex.members.dropLast(1)))
                        }
                    }
                    suggestedPrefixLocal is RegularExpression.Repeat && suggestedPrefixLocal.min > 0 && suggestedPrefixLocal.expression == ex -> {
                        val moveToMembers = suggestedPrefixLocal.copy(min = suggestedPrefixLocal.min - 1)
                        newItems = newItems.mapTo(HashSet()) { directionalConcat(moveToMembers, it) }
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

fun <T> simplify(regex: RegularExpression<T>): RegularExpression<T> {
    when (regex) {
        is RegularExpression.Terminal -> return regex
        is RegularExpression.Concatenate -> {
            val builder = ConcatBuilder<T>()
            builder.add(regex)
            return builder.build()
        }
        is RegularExpression.Or -> {
            val builder = OrBuilder<T>()
            builder.add(regex)
            return builder.build()
        }
        is RegularExpression.Repeat -> {
            if (regex.max == 0) return RegularExpression.empty()
            val simple = simplify(regex.expression)
            if (regex.min == 1 && regex.max == 1) return simple
            if (simple == RegularExpression.empty<T>()) return simple
            if (simple == RegularExpression.nothing<T>()) {
                if (regex.min == 0) return RegularExpression.empty<T>()
                else return RegularExpression.nothing<T>()
            }
            if (simple is RegularExpression.Repeat) {
                val min1 = regex.min
                val min2 = simple.min
                val max1 = regex.max
                val max2 = simple.max
                if (min1 <= 1 && min2 <= 1 && (max1 == null || max2 == null))
                    return RegularExpression.Repeat(simple.expression, min1 * min2, null)
                if (min1 == max1 && min2 == max2)
                    return RegularExpression.Repeat(simple.expression, min1 * min2, min1 * min2)
            }
            return regex.copy(expression = simple)
        }
        else -> throw AssertionError()
    }
}
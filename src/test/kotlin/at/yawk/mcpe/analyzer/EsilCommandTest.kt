package at.yawk.mcpe.analyzer

import org.testng.Assert
import org.testng.annotations.Test

/**
 * @author yawkat
 */
class EsilCommandTest {
    @Test
    fun `mov`() = Assert.assertEquals(
            EsilCommand.parse("r0,r5,="),
            listOf(
                    EsilCommand.Register("r0"),
                    EsilCommand.Register("r5"),
                    EsilCommand.Operation.ASSIGN
            )
    )

    @Test
    fun `blx`() = Assert.assertEquals(
            EsilCommand.parse("4,pc,+,lr,=,12345,pc,="),
            listOf(
                    EsilCommand.Value(4),
                    EsilCommand.Register("pc"),
                    EsilCommand.Operation.ADD,
                    EsilCommand.Register("lr"),
                    EsilCommand.Operation.ASSIGN,
                    EsilCommand.Value(12345),
                    EsilCommand.Register("pc"),
                    EsilCommand.Operation.ASSIGN
            )
    )
}
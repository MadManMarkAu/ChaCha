Imports System.IO

Module Module1
    ' Verification test, according to https://tools.ietf.org/html/draft-strombergson-chacha-test-vectors-00#page-31
    Sub Main()
        Dim abytKey() As Byte = New Byte() {&HC4, &H6E, &HC1, &HB1, &H8C, &HE8, &HA8, &H78, &H72, &H5A, &H37, &HE7, &H80, &HDF, &HB7, &H35, &H1F, &H68, &HED, &H2E, &H19, &H4C, &H79, &HFB, &HC6, &HAE, &HBE, &HE1, &HA6, &H67, &H97, &H5D}
        Dim abytIV() As Byte = New Byte() {&H1A, &HDA, &H31, &HD5, &HCF, &H68, &H82, &H21}
        Dim abytInput(127) As Byte
        Dim abytOutput(127) As Byte

        Using msSource As New MemoryStream(abytInput)
            Using csStream As New ChachaStream(msSource, abytKey, abytIV)
                csStream.Read(abytOutput, 0, abytOutput.Length)
            End Using
        End Using
        DisplayBytes(abytOutput)

        Console.WriteLine()
        Console.ReadKey()
    End Sub

    Private Sub DisplayBytes(abytData() As Byte)
        Dim intPos As Integer

        For intIndex As Integer = 0 To abytData.Length - 1
            If intPos > 0 Then
                Console.Write(" ")
            End If
            Console.Write(abytData(intIndex).ToString("X2"))
            intPos += 1
            If intPos >= 8 Then
                intPos = 0
                Console.WriteLine()
            End If
        Next

        If intPos > 0 Then
            Console.WriteLine()
        End If
    End Sub
End Module

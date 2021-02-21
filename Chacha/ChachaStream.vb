Imports System.IO
Imports System.Text

''' <summary>
''' Provides a Stream object implementing the Chacha encryption algorithm
''' </summary>
Public Class ChachaStream
    Inherits Stream

    Private m_sBackingStream As Stream
    Private m_abytKey() As Byte
    Private m_abytIV() As Byte
    Private m_intRounds As Integer
    Private m_abytStream() As Byte
    Private m_lngCurrentBlock As ULong
    Private m_intStreamPos As Integer

    Public Overrides ReadOnly Property CanRead As Boolean
        Get
            Return m_sBackingStream.CanRead
        End Get
    End Property

    Public Overrides ReadOnly Property CanSeek As Boolean
        Get
            Return m_sBackingStream.CanSeek
        End Get
    End Property

    Public Overrides ReadOnly Property CanWrite As Boolean
        Get
            Return m_sBackingStream.CanWrite
        End Get
    End Property

    Public Overrides ReadOnly Property Length As Long
        Get
            Return m_sBackingStream.Length
        End Get
    End Property

    Public Overrides Property Position As Long
        Get
            Return m_sBackingStream.Position
        End Get
        Set(value As Long)
            m_sBackingStream.Position = value
            SetCryptPos(value)
        End Set
    End Property

    ' 256-bit (32-byte) key
    ' 64-bit (8-byte) IV
    ''' <summary>
    ''' Creates a new instance of ChachaStream, specifying the key, IV and round information.
    ''' </summary>
    ''' <param name="sBackingStream">The stream to read/write to.</param>
    ''' <param name="abytKey">The 128- or 256-bit (16- or 32-byte) encryption key.</param>
    ''' <param name="abytIV">the 64-bit (8-byte) initialization vector, or nonce.</param>
    ''' <param name="intRounds">The number of "salsa" mixing rounds to apply to the keystream data.</param>
    Public Sub New(sBackingStream As Stream, abytKey() As Byte, abytIV() As Byte, Optional intRounds As Integer = 20)
        m_sBackingStream = sBackingStream
        m_abytKey = abytKey
        m_abytIV = abytIV
        m_intRounds = intRounds
        m_abytStream = GetKeyStream(m_abytKey, m_lngCurrentBlock, m_abytIV, m_intRounds)
    End Sub

    Public Overrides Sub Flush()
        m_sBackingStream.Flush()
    End Sub

    Public Overrides Sub SetLength(value As Long)
        m_sBackingStream.SetLength(value)
    End Sub

    Public Overrides Sub Write(buffer() As Byte, offset As Integer, count As Integer)
        Dim abytCipher() As Byte

        abytCipher = Crypt(buffer, offset, count)

        m_sBackingStream.Write(abytCipher, 0, count)
    End Sub

    Public Overrides Function Seek(offset As Long, origin As SeekOrigin) As Long
        Dim lngPosition As Long

        lngPosition = m_sBackingStream.Seek(offset, origin)

        SetCryptPos(lngPosition)

        Return lngPosition
    End Function

    Public Overrides Function Read(buffer() As Byte, offset As Integer, count As Integer) As Integer
        Dim abytCipher(count - 1) As Byte
        Dim abytPlain() As Byte
        Dim intReadSize As Integer

        intReadSize = m_sBackingStream.Read(abytCipher, 0, count)
        abytPlain = Crypt(abytCipher, 0, intReadSize)

        Array.Copy(abytPlain, 0, buffer, offset, intReadSize)

        Return intReadSize
    End Function

    Public Function Crypt(abytInput() As Byte, intOffset As Integer, intLength As Integer) As Byte()
        Dim abytOutput(intLength - 1) As Byte

        For intIndex As Integer = 0 To intLength - 1
            abytOutput(intIndex) = abytInput(intIndex + intOffset) Xor m_abytStream(m_intStreamPos)
            m_intStreamPos += 1
            If m_intStreamPos >= 64 Then
                m_intStreamPos = 0
                m_lngCurrentBlock += 1
                m_abytStream = GetKeyStream(m_abytKey, m_lngCurrentBlock, m_abytIV, m_intRounds)
            End If
        Next

        Return abytOutput
    End Function

    Private Sub SetCryptPos(lngPosition As Long)
        m_lngCurrentBlock = lngPosition >> 6
        m_intStreamPos = lngPosition And 63
        m_abytStream = GetKeyStream(m_abytKey, m_lngCurrentBlock, m_abytIV, m_intRounds)
    End Sub

    Private Shared Function GetKeyStream(abytKey() As Byte, lngBlockNum As ULong, abytIV() As Byte, intRounds As Integer) As Byte()
        Dim aintKeyBlock() As UInteger
        Dim abytStream(63) As Byte

        aintKeyBlock = BuildKeyBlock(abytKey, lngBlockNum, abytIV)
        aintKeyBlock = Salsa20(aintKeyBlock, intRounds)

        For intIndex As Integer = 0 To 15
            Array.Copy(BitConverter.GetBytes(aintKeyBlock(intIndex)), 0, abytStream, intIndex << 2, 4)
        Next

        Return abytStream
    End Function

    Private Shared Function BuildKeyBlock(abytKey() As Byte, lngBlockNum As ULong, abytIV() As Byte) As UInteger()
        Dim abytConst() As Byte
        Dim abytBlockNum() As Byte = BitConverter.GetBytes(lngBlockNum)
        Dim aintBlock(15) As UInteger

        If abytKey.Length = 32 Then
            abytConst = Encoding.ASCII.GetBytes("expand 32-byte k")

            aintBlock(0) = BitConverter.ToUInt32(abytConst, 0)
            aintBlock(1) = BitConverter.ToUInt32(abytConst, 4)
            aintBlock(2) = BitConverter.ToUInt32(abytConst, 8)
            aintBlock(3) = BitConverter.ToUInt32(abytConst, 12)
            aintBlock(4) = BitConverter.ToUInt32(abytKey, 0)
            aintBlock(5) = BitConverter.ToUInt32(abytKey, 4)
            aintBlock(6) = BitConverter.ToUInt32(abytKey, 8)
            aintBlock(7) = BitConverter.ToUInt32(abytKey, 12)
            aintBlock(8) = BitConverter.ToUInt32(abytKey, 16)
            aintBlock(9) = BitConverter.ToUInt32(abytKey, 20)
            aintBlock(10) = BitConverter.ToUInt32(abytKey, 24)
            aintBlock(11) = BitConverter.ToUInt32(abytKey, 28)
            aintBlock(12) = BitConverter.ToUInt32(abytBlockNum, 0)
            aintBlock(13) = BitConverter.ToUInt32(abytBlockNum, 4)
            aintBlock(14) = BitConverter.ToUInt32(abytIV, 0)
            aintBlock(15) = BitConverter.ToUInt32(abytIV, 4)
        ElseIf abytKey.Length = 16 Then
            abytConst = Encoding.ASCII.GetBytes("expand 16-byte k")

            aintBlock(0) = BitConverter.ToUInt32(abytConst, 0)
            aintBlock(1) = BitConverter.ToUInt32(abytConst, 4)
            aintBlock(2) = BitConverter.ToUInt32(abytConst, 8)
            aintBlock(3) = BitConverter.ToUInt32(abytConst, 12)
            aintBlock(4) = BitConverter.ToUInt32(abytKey, 0)
            aintBlock(5) = BitConverter.ToUInt32(abytKey, 4)
            aintBlock(6) = BitConverter.ToUInt32(abytKey, 8)
            aintBlock(7) = BitConverter.ToUInt32(abytKey, 12)
            aintBlock(8) = BitConverter.ToUInt32(abytKey, 0)
            aintBlock(9) = BitConverter.ToUInt32(abytKey, 4)
            aintBlock(10) = BitConverter.ToUInt32(abytKey, 8)
            aintBlock(11) = BitConverter.ToUInt32(abytKey, 12)
            aintBlock(12) = BitConverter.ToUInt32(abytBlockNum, 0)
            aintBlock(13) = BitConverter.ToUInt32(abytBlockNum, 4)
            aintBlock(14) = BitConverter.ToUInt32(abytIV, 0)
            aintBlock(15) = BitConverter.ToUInt32(abytIV, 4)
        Else
            Throw New ArgumentException("Invalid key length")
        End If

        Return aintBlock
    End Function

    Private Shared Function Salsa20(ByRef aintInput() As UInteger, intRounds As Integer) As UInteger()
        Dim aintOutput(15) As UInteger

        For intIndex As Integer = 0 To 15
            aintOutput(intIndex) = aintInput(intIndex)
        Next

        While intRounds > 0
            QuarterRound(aintOutput(0), aintOutput(4), aintOutput(8), aintOutput(12))
            QuarterRound(aintOutput(1), aintOutput(5), aintOutput(9), aintOutput(13))
            QuarterRound(aintOutput(2), aintOutput(6), aintOutput(10), aintOutput(14))
            QuarterRound(aintOutput(3), aintOutput(7), aintOutput(11), aintOutput(15))
            QuarterRound(aintOutput(0), aintOutput(5), aintOutput(10), aintOutput(15))
            QuarterRound(aintOutput(1), aintOutput(6), aintOutput(11), aintOutput(12))
            QuarterRound(aintOutput(2), aintOutput(7), aintOutput(8), aintOutput(13))
            QuarterRound(aintOutput(3), aintOutput(4), aintOutput(9), aintOutput(14))

            intRounds -= 2
        End While

        For intIndex As Integer = 0 To 15
            aintOutput(intIndex) = Plus(aintOutput(intIndex), aintInput(intIndex))
        Next

        Return aintOutput
    End Function

    Private Shared Sub QuarterRound(ByRef intA As UInteger, ByRef intB As UInteger, ByRef intC As UInteger, ByRef intD As UInteger)
        intA = Plus(intA, intB)
        intD = Rotate(intD Xor intA, 16)
        intC = Plus(intC, intD)
        intB = Rotate(intB Xor intC, 12)
        intA = Plus(intA, intB)
        intD = Rotate(intD Xor intA, 8)
        intC = Plus(intC, intD)
        intB = Rotate(intB Xor intC, 7)
    End Sub

    Private Shared Function Plus(intLeft As UInteger, intRight As UInteger) As UInteger
        Return (CULng(intLeft) + intRight) And &HFFFFFFFFUL
    End Function

    Private Shared Function Rotate(intValue As UInteger, intPlaces As Integer) As UInteger
        Return (intValue << intPlaces) Or (intValue >> (32 - intPlaces))
    End Function
End Class

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Mifare_App.Mifare;
using PCSC;
using PCSC.Iso7816;

namespace MifareAppTest.Mifare
{
    class MifareCard
    {
        private const byte CLA = 0xFF;
        private readonly IIsoReader _isoReader;

        public MifareCard(IIsoReader isoReader)
        {
            _isoReader = isoReader ?? throw new ArgumentNullException(nameof(isoReader));
        }

        public bool LoadKey(KeyStructure keyStructure, byte keyNumber, byte[] key)
        {
            var loadKeyCmd = new CommandApdu(IsoCase.Case3Short, SCardProtocol.Any)
            {
                CLA = CLA,
                Instruction = InstructionCode.ExternalAuthenticate
                P1 = (byte)keyStructure,
                P2 = keyNumber,
                Data = key
            };

            Debug.WriteLine($"LOAD KEY COMMAND: {BitConverter.ToString(loadKeyCmd.ToArray())}");
            var response = _isoReader.Transmit(loadKeyCmd);
            Debug.WriteLine($"SW1 SW2 = {response.SW1:X2} {response.SW2:X2}");

            return IsSuccess(response);
        }

        public bool Authenticate(byte msb, byte lsb, KeyType keyType, byte keyNumber)
        {
            var authBlock = new GeneralAuthenticate
            {
                KeyNumber = keyNumber,
                KeyType = keyType,
                Lsb = lsb,
                Msb = msb
            };

            var authCmd = new CommandApdu(IsoCase.Case3Short, SCardProtocol.Any)
            {
                CLA = CLA,
                Instruction = InstructionCode.InternalAuthenticate,
                P1 = 0x00,
                P2 = 0x00,
                Data = authBlock.ToArray()
            };

            Debug.WriteLine($"GENERAL AUTHENTICATE: {BitConverter.ToString(authCmd.ToArray())}");
            var response = _isoReader.Transmit(authCmd);
            Debug.WriteLine($"SW1 SW2 = {response.SW1:X2} {response.SW2:X2}");

            return IsSuccess(response);
        }

        public byte[] ReadBinary(byte msb, byte lsb, int size) => throw new NotImplementedException();
        public bool UpdateBinary(byte msb, byte lsb, byte[] data) => throw new NotImplementedException();

        private bool IsSuccess(Response response) => (response.SW1 == (byte) SW1Code.Normal) && (response.SW1 == 0x00);
    }
}

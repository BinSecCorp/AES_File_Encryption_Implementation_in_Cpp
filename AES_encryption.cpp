#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <cstring>

typedef bool boolean;
typedef enum exec {encrypt, decrypt} exec;

class AES
{
    private:
        uint32_t Rkeys[11][4];     //RoundKeys: 11 128 bit round keys as 4 32 bit words each;

        //Byte Manipulation Processes:
        void XorRKey(uint32_t Rkey[4]);
        void Subbytes(boolean reverse);
        void MixColumns(boolean reverse);
        void ShiftRows(boolean reverse);


        /*/Subprocess declarations /*/
        //used by Expandkey:
        int ValRkey(int, int);
        int ValRkeyinit(int);
        int Rcon(int);      //Rcon table used by ValRkeyinit
        int ROTATE(int);    //Rotate bits of a 32 bit integer 8 bits left;

        //used by MixColumns:
        uint8_t Three(uint8_t);
        uint8_t Two(uint8_t);

        uint8_t Nine(uint8_t input);
        uint8_t xb(uint8_t input);
        uint8_t xd(uint8_t input);
        uint8_t xe(uint8_t input);

    public:


        uint32_t Cipherkey[4];     //Cipherkey: 128 bit cipher key as 4 32 bit words(input);
        uint8_t Block[4][4];      //Content Block: 128 bit block as 16 bytes(4x4);


            // default constructor sets all arrays to zeros
        AES()
        {
            memset(Rkeys, 0, sizeof(Rkeys));
            memset(Cipherkey, 0, sizeof(Cipherkey));
            memset(Block, 0, sizeof(Block));
        }


        /*/ Main Process Declarations /*/

        void Exec(exec process);         //Encryption main process, decrypts the content within uint8_t Block;
        void Expandkey (void);      //Expands cipherkey into 11 roundkeys;
        void DumpCipherKey(void);

};

using namespace std;
/*/ Entry Point /*/
int main(int argc, char *argv[])
{
    exec process;

    if(argv[1][1] == 'e')
    {
        std::cout << "Encryption = True\n";
        process = encrypt;
    }
    else
    {
        std::cout << "Encryption = False\n";
        process = decrypt;
    }

    AES EncryptionProcess;


    /*/ This section is responsibel for the gathering of the hex key from the arguments. /*/

    char string_key_word[8] = {0}; //holds a cipherkey word as char string
    int char_index = 0; // character index of the input; does not reset for each word

    for (int cipherkey_index = 0; cipherkey_index < 4; cipherkey_index++)
    {
        for (int character = 0; character < 8; character++) //loops after reading each 32-bit(8 char) word 
        {
            string_key_word[character] = argv[4][char_index]; // reads cipherkey from the 4th input section in the command prompt
            char_index ++;
        }
       EncryptionProcess.Cipherkey[cipherkey_index] = (int) strtoul(string_key_word, NULL, 16); //reads string_key_word as a hex number
    }
    EncryptionProcess.Expandkey();

    /*/ End section /*/

    char_index = 0;    

    ifstream fileBuffer(argv[2], ios::in|ios::binary);
    ofstream outputBuffer(argv[3], ios::out|ios::binary);

    if (fileBuffer.is_open())
    {
        /*/ this section gets the file length in bytes/*/
        fileBuffer.seekg(0, ios::end);
        int filelen = fileBuffer.tellg();
        cout << "FILE LENGTH: " << filelen << "\n";

        /*/ read bytes to buffer /*/
        fileBuffer.seekg(0, ios::beg);
        char buffer[16];

        int bytes_complete = 0; // keeps track of how many bytes have been completed for progress update
        float percent_complete;
        while (fileBuffer.read(buffer, sizeof(buffer)))
        {
            /*/ do stuff /*/
            EncryptionProcess.Block[0][0] = buffer[0];
            EncryptionProcess.Block[0][1] = buffer[1];
            EncryptionProcess.Block[0][2] = buffer[2];
            EncryptionProcess.Block[0][3] = buffer[3];
            EncryptionProcess.Block[1][0] = buffer[4];
            EncryptionProcess.Block[1][1] = buffer[5];
            EncryptionProcess.Block[1][2] = buffer[6];
            EncryptionProcess.Block[1][3] = buffer[7];
            EncryptionProcess.Block[2][0] = buffer[8];
            EncryptionProcess.Block[2][1] = buffer[9];
            EncryptionProcess.Block[2][2] = buffer[10];
            EncryptionProcess.Block[2][3] = buffer[11];
            EncryptionProcess.Block[3][0] = buffer[12];
            EncryptionProcess.Block[3][1] = buffer[13];
            EncryptionProcess.Block[3][2] = buffer[14];
            EncryptionProcess.Block[3][3] = buffer[15];

            EncryptionProcess.Exec(process);

            int t = 0;
            for (int p = 0; p < 4; p++)
            {
                for (int q = 0; q < 4; q++)
                {
                    buffer[t] = EncryptionProcess.Block[p][q];
                    t++;
                }
            }

            outputBuffer.write(buffer, sizeof(buffer)); // write resulting buffer to output
            for (int x = 0; x < 16; x ++){buffer[x] = 0x00;} // clears buffer
            
            bytes_complete = bytes_complete + 16;
            
            /*/ prints out percentage and bytes complete every 100 kilobyte /*/
            if (bytes_complete % (100*1024) == 0)
            {
    
                percent_complete = ((float) bytes_complete / (float) filelen )* 100.0;
                printf("%.2f", percent_complete);
                cout << "% complete (" << bytes_complete << " bytes)\n"; 
            }
        }

        cout << "Copying remaining bytes...\n";
        /*/ copys over the remaining data /*/
        char c[1];
        for (int i = filelen - filelen % 16; i < filelen; i++)
        {
            /*/ copy data over other file /*/
            fileBuffer.read(c, sizeof(c));
            outputBuffer.write(c, sizeof(c));
        }

        cout << "Process Complete!\n";
    }

}


void AES::Expandkey(void)
{

    /*/ initializes the first roundkey /*/

    Rkeys[0][0] = Cipherkey[0];
    Rkeys[0][1] = Cipherkey[1];
    Rkeys[0][2] = Cipherkey[2];
    Rkeys[0][3] = Cipherkey[3];


    /*/ Loop /*/

    /*/ Key loop /*/
    for (int key = 1; key < 11; key ++)
    {
        //printf("\tKey %02d : ", key);
        /*/ Sub loop /*/
        for (int word = 0; word < 4; word++){
            if (word == 0)
            {Rkeys[key][word] = ValRkeyinit(key);}
            else
            {Rkeys[key][word] = ValRkey(key, word);}
            

        }
    }
}


void AES::Exec(exec process)
{

    if(process == encrypt)
    {
        XorRKey(Rkeys[0]);
        
        int Round;
        for(Round = 1; Round < 10; Round ++)
        {
            Subbytes(false);
            ShiftRows(false);
            MixColumns(false);
            XorRKey(Rkeys[Round]);
        }

        Subbytes(false);
        ShiftRows(false);
        XorRKey(Rkeys[10]);
    }

    else
    {
        XorRKey(Rkeys[10]);
        ShiftRows(true);
        Subbytes(true);
        
        int Round;
        for(Round = 9; Round > 0; Round = Round -1)
        {
            XorRKey(Rkeys[Round]);
            MixColumns(true);
            ShiftRows(true);
            Subbytes(true);
        }

        XorRKey(Rkeys[0]);
    }
}



void AES::DumpCipherKey(void)
{
    for(int word_index = 0; word_index < 4; word_index ++)
    {
        std::cout << Cipherkey[word_index];
    }
    std::cout << "\n";
}



void AES::Subbytes(boolean reverse)
{ 
    uint8_t SBox[16][16] = 
    {
        {0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
        {0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
        {0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
        {0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
        {0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
        {0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
        {0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
        {0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
        {0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
        {0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
        {0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
        {0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
        {0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
        {0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
        {0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
        {0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}
    };

    uint8_t RSbox[16][16] =
    {
        {0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb},
        {0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb},
        {0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e},
        {0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25},
        {0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92},
        {0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84},
        {0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06},
        {0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b},
        {0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73},
        {0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e},
        {0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b},
        {0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4},
        {0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f},
        {0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef},
        {0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61},
        {0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d}
    };
    
    int Column, Row;
    if(reverse == true)
    {
    for(Row = 0; Row < 4; Row ++)
    {
        for(Column = 0; Column < 4; Column ++)
        {
            int Lower, Upper;
            Lower = Block[Row][Column] & 0xf;
            Upper = Block[Row][Column] >> 4;
            Block[Row][Column] = RSbox[Upper][Lower];
        }
    }
    }

    else
    {
        for(Row = 0; Row < 4; Row ++)
        {
        for(Column = 0; Column < 4; Column ++)
        {
            int Lower, Upper;
            Lower = Block[Row][Column] & 0xf;
            Upper = Block[Row][Column] >> 4;
            Block[Row][Column] = SBox[Upper][Lower];
        }
    }
    }


}



void AES::ShiftRows(boolean reverse)
{
    uint8_t SBlock[4][4];

    if(reverse == false)
    {

    SBlock[1][0] = Block[1][3];
    SBlock[1][1] = Block[1][0];
    SBlock[1][2] = Block[1][1];
    SBlock[1][3] = Block[1][2];

    SBlock[2][0] = Block[2][3];
    SBlock[2][1] = Block[2][0];
    SBlock[2][2] = Block[2][1];
    SBlock[2][3] = Block[2][2];

    SBlock[3][0] = Block[3][3];
    SBlock[3][1] = Block[3][0];
    SBlock[3][2] = Block[3][1];
    SBlock[3][3] = Block[3][2];
    }

    else
    {
    SBlock[1][0] = Block[1][1];
    SBlock[1][1] = Block[1][2];
    SBlock[1][2] = Block[1][3];
    SBlock[1][3] = Block[1][0];

    SBlock[2][0] = Block[2][1];
    SBlock[2][1] = Block[2][2];
    SBlock[2][2] = Block[2][3];
    SBlock[2][3] = Block[2][0];

    SBlock[3][0] = Block[3][1];
    SBlock[3][1] = Block[3][2];
    SBlock[3][2] = Block[3][3];
    SBlock[3][3] = Block[3][0];
    }

    Block[1][0] = SBlock[1][0];
    Block[1][1] = SBlock[1][1];
    Block[1][2] = SBlock[1][2];
    Block[1][3] = SBlock[1][3];

    Block[2][0] = SBlock[2][0];
    Block[2][1] = SBlock[2][1];
    Block[2][2] = SBlock[2][2];
    Block[2][3] = SBlock[2][3];

    Block[3][0] = SBlock[3][0];
    Block[3][1] = SBlock[3][1];
    Block[3][2] = SBlock[3][2];
    Block[3][3] = SBlock[3][3];
}



void AES::XorRKey(uint32_t Rkey[4])
{
    uint8_t ByteRkey[4][4] = {0};

    ByteRkey[0][0] = (Rkey[0] & 0xff000000) >> 24;
    ByteRkey[0][1] = (Rkey[0] & 0xff0000) >> 16;
    ByteRkey[0][2] = (Rkey[0] & 0xff00) >> 8;
    ByteRkey[0][3] = Rkey[0]  & 0xff;

    ByteRkey[1][0] = (Rkey[1] & 0xff000000) >> 24;
    ByteRkey[1][1] = (Rkey[1] & 0xff0000) >> 16;
    ByteRkey[1][2] = (Rkey[1] & 0xff00) >> 8;
    ByteRkey[1][3] = Rkey[1]  & 0xff;

    ByteRkey[2][0] = (Rkey[2] & 0xff000000) >> 24;
    ByteRkey[2][1] = (Rkey[2] & 0xff0000) >> 16;
    ByteRkey[2][2] = (Rkey[2] & 0xff00) >> 8;
    ByteRkey[2][3] = Rkey[2]  & 0xff;

    ByteRkey[3][0] = (Rkey[3] & 0xff000000) >> 24;
    ByteRkey[3][1] = (Rkey[3] & 0xff0000) >> 16;
    ByteRkey[3][2] = (Rkey[3] & 0xff00) >> 8;
    ByteRkey[3][3] = Rkey[3]  & 0xff;

    int x,y, XorByte;
    for (x = 0; x < 4; x ++)
    {
        for (y = 0; y < 4; y ++)
        {   
            XorByte = Block[x][y] ^ ByteRkey[x][y];
            Block[x][y] = XorByte;
        }
    }
}

void AES::MixColumns(boolean reverse)
{
    if(reverse == false)
    {
    uint8_t tmp_in[4], tmp_out[4];
    int p,q;
    for (q=0; q<4; q++)
    {

        for (p=0; p<4; p++)
        {
            tmp_in[p] = Block[p][q];
        }

        tmp_out[0] = Two(tmp_in[0]) ^ Three(tmp_in[1]) ^ tmp_in[2] ^ tmp_in[3];
        tmp_out[1] = tmp_in[0] ^ Two(tmp_in[1]) ^ Three(tmp_in[2]) ^ tmp_in[3];
        tmp_out[2] = tmp_in[0] ^ tmp_in[1] ^ Two(tmp_in[2]) ^ Three(tmp_in[3]);
        tmp_out[3] = Three(tmp_in[0]) ^ tmp_in[1] ^ tmp_in[2] ^ Two(tmp_in[3]);

        for (p=0; p<4; p++)
        {
            Block[p][q] = tmp_out[p];
        }
    }
    }

    else
    {
    uint8_t tmp_in[4], tmp_out[4];
    int p,q;
    for (q=0; q<4; q++)
    {

        for (p=0; p<4; p++)
        {
            tmp_in[p] = Block[p][q];
        }

        tmp_out[0] = xe(tmp_in[0]) ^ xb(tmp_in[1]) ^ xd(tmp_in[2]) ^ Nine(tmp_in[3]);
        tmp_out[1] = Nine(tmp_in[0]) ^ xe(tmp_in[1]) ^ xb(tmp_in[2]) ^ xd(tmp_in[3]);
        tmp_out[2] = xd(tmp_in[0]) ^ Nine(tmp_in[1]) ^ xe(tmp_in[2]) ^ xb(tmp_in[3]);
        tmp_out[3] = xb(tmp_in[0]) ^ xd(tmp_in[1]) ^ Nine(tmp_in[2]) ^ xe(tmp_in[3]);

        for (p=0; p<4; p++)
        {
            Block[p][q] = tmp_out[p];
        }
    }
    }
}

/*/ Sub Declarations /*/

//Key Expansion:
int AES::ValRkey(int key, int w) //returns value of roundkey words;
{
    return Rkeys[key - 1][w] ^ Rkeys[key][w - 1];
}

int AES::ValRkeyinit(int key)    //returns value of roundkey words index 0;
{
    return Rkeys[key-1][0] ^ ROTATE(Rkeys[key-1][3]) ^ Rcon(key);
}

int AES::Rcon(int i)             //Rcon table for ValRkeyinit;
{
    int RCONDB[10] = {2,4,8,16,32,64,128,27,54,108};
    return RCONDB[i - 1];
}

int AES::ROTATE(int x)           //Rotate bits of a 32 bit value 8 bits left;
{
    int Cbits = x << 24;
    x = x >> 8;
    return x | Cbits;
}

//Mix Column:
uint8_t AES::Two(uint8_t input)
{
    uint8_t output = input << 1;
    if (input >> 7 == 0x01)
    {
        output = output ^ 0x1b;
    }
    return output;
}

uint8_t AES::Three(uint8_t input)
{
    uint8_t output_2 = input << 1;
    if (input >> 7 == 0x01)
    {
        output_2 = output_2 ^ 0x1b;
    }
    return output_2 ^ input;
}


uint8_t AES::Nine(uint8_t input)
{
    return Two(Two(Two(input))) ^ input;
}

uint8_t AES::xb(uint8_t input)
{
    return Two(Two(Two(input)) ^ input) ^ input;
}

uint8_t AES::xd(uint8_t input)
{
    return Two(Two(Two(input) ^ input)) ^ input;
}

uint8_t AES::xe(uint8_t input)
{
    return Two(Two(Two(input) ^ input) ^ input);
}

#include <chrono>
#include <dsa.h>
#include <rsa.h>
#include <des.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <iostream>
#include <osrng.h>

using namespace std;
using namespace std::chrono;
using namespace CryptoPP;

auto runAES(string plaintext)
{

	//symmetric key 
	//AES
	AutoSeededRandomPool prng;
	SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte initVector[AES::BLOCKSIZE];
	prng.GenerateBlock(initVector, sizeof(initVector));

	string ciphertext;
	string decryptedtext;

	//encrypt

	auto start = high_resolution_clock::now();

	AES::Encryption aesEncryption(key, AES::DEFAULT_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, initVector);

	StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();

	auto stop = high_resolution_clock::now();

	auto durationEncryption = duration_cast<microseconds>(stop - start);

	//print ciphertext
	cout << "AES ciphertext: " << ciphertext << endl;
	cout << "Duration for AES encryption: " << durationEncryption.count() << " microseconds" << endl;

	//decrypt

	start = high_resolution_clock::now();

	AES::Decryption aesDecryption(key, AES::DEFAULT_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, initVector);

	StreamTransformationFilter stfDecryptor(cbcDecryption, new StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
	stfDecryptor.MessageEnd();

	stop = high_resolution_clock::now();

	auto durationDecryption = duration_cast<microseconds>(stop - start);

	//print decryptedtext
	cout << "AES decryptedtext: " << decryptedtext << endl;
	cout << "Duration for AES decryption: " << durationDecryption.count() << " microseconds" << endl;

	auto totalTime = durationEncryption + durationDecryption;
	cout << "Total time for AES encryption and decryption: "<< totalTime.count() << " microseconds" << endl << endl;
	return totalTime;
}

auto run3DES(string plaintext)
{
	//symmetric key 
	//3DES - Three keys
	
	AutoSeededRandomPool prng;

	SecByteBlock key(0x00, DES_EDE3::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte initVector[DES_EDE3::BLOCKSIZE];
	prng.GenerateBlock(initVector, sizeof(initVector));

	string ciphertext;
	string decryptedtext;

	//encrypt
	auto start = high_resolution_clock::now();

	DES_EDE3::Encryption desEncryption(key, DES_EDE3::DEFAULT_KEYLENGTH);
	CBC_Mode<DES_EDE3>::Encryption cbcEncryption;
	cbcEncryption.SetKeyWithIV(key, key.size(), initVector);

	StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();

	auto stop = high_resolution_clock::now();

	auto durationEncryption = duration_cast<microseconds>(stop - start);

	//print ciphertext
	cout << "3DES ciphertext: " << ciphertext << endl;
	cout << "Duration for 3DES encryption: " << durationEncryption.count() << " microseconds" << endl;

	//decrypt

	start = high_resolution_clock::now();

	DES_EDE3::Decryption desDecryption(key, DES_EDE3::DEFAULT_KEYLENGTH);
	CBC_Mode<DES_EDE3>::Decryption cbcDecryption;
	cbcDecryption.SetKeyWithIV(key, key.size(), initVector);
	
	StreamTransformationFilter stfDecryptor(cbcDecryption, new StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
	stfDecryptor.MessageEnd();

	stop = high_resolution_clock::now();

	auto durationDecryption = duration_cast<microseconds>(stop - start);

	//print decryptedtext
	cout << "3DES decryptedtext: " <<decryptedtext << endl;
	cout << "Duration for 3DES decryption: " << durationDecryption.count() << " microseconds" << endl;

	auto totalTime = durationEncryption + durationDecryption;
	cout << "Total time for 3DES encryption and decryption: " << totalTime.count() << " microseconds" << endl << endl;
	return totalTime;
}

auto runRSA(string plaintext)
{
	//asymmetric key
	//RSA

	AutoSeededRandomPool rng;
	InvertibleRSAFunction parameters;
	parameters.GenerateRandomWithKeySize(rng, 1536);

	RSA::PrivateKey privateKey(parameters);
	RSA::PublicKey publicKey(parameters);


	//encryption

	auto start = high_resolution_clock::now();

	RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
	size_t ecl = encryptor.CiphertextLength(plaintext.size());
	SecByteBlock ciphertext(ecl);
	encryptor.Encrypt(rng, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size(), ciphertext);

	auto stop = high_resolution_clock::now();

	auto durationEncryption = duration_cast<microseconds>(stop - start);

	//print ciphertext
	string ciphertextStr(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
	cout << "RSA ciphertext: " << ciphertextStr << endl;
	cout << "Duration for RSA encryption: " << durationEncryption.count() << " microseconds" << endl;



	//decryption

	start = high_resolution_clock::now();

	RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
	size_t dpl = decryptor.MaxPlaintextLength(ciphertext.size());
	SecByteBlock decryptedtext(dpl);
	DecodingResult result = decryptor.Decrypt(rng, ciphertext, ciphertext.size(), decryptedtext);

	decryptedtext.resize(result.messageLength); 

	stop = high_resolution_clock::now();

	auto durationDecryption = duration_cast<microseconds>(stop - start);

	//print decryptedtext
	string decryptedtextStr(reinterpret_cast<const char*>(decryptedtext.data()), decryptedtext.size());
	cout << "RSA decryptedtext: " << decryptedtextStr << endl;
	cout << "Duration for RSA decryption: " << durationDecryption.count() << " microseconds" << endl;

	auto totalTime = durationEncryption + durationDecryption;
	cout << "Total time for RSA encryption and decryption: " << totalTime.count() << " microseconds" << endl << endl;
	return totalTime;
}

int main()
{
	//we used a complex and long plaintext to capture reality
	/*string plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras eget neque sed nibh pellentesque consectetur. Duis condimentum nulla luctus odio placerat, quis condimentum lectus mollis. Nam iaculis tempor leo, ac porttitor metus mattis sit amet. Nulla id ligula a magna mollis aliquam vel nec orci. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Pellentesque imperdiet eleifend cursus. In non ipsum sit amet risus ultrices porta id vel nisi. Nam suscipit auctor dui. Donec efficitur tincidunt lobortis. Donec quis massa lobortis dui malesuada pharetra. Phasellus sit amet augue ac erat varius ultrices."
		"\nSed massa urna, euismod id nisi non, imperdiet tempus tellus.Donec venenatis eu sem quis commodo.Suspendisse sit amet nulla justo.Morbi nec ipsum tristique, congue lectus ut, porta leo.Aliquam varius blandit sapien, eget ornare neque aliquet a.Quisque congue pulvinar leo vitae convallis.Nam vitae ligula quis sem faucibus vestibulum."
		"\nMauris sapien tellus, consequat eget aliquet a, blandit nec augue.Praesent a sem id sapien iaculis facilisis eget eu lectus.Donec quis rhoncus nulla, sit amet sodales est.Sed venenatis porta iaculis.Praesent maximus sit amet massa eget bibendum.Morbi augue mauris, tincidunt id diam et, accumsan vestibulum nisi.Mauris ut rhoncus nibh.Lorem ipsum dolor sit amet, consectetur adipiscing elit.Proin in metus rutrum, interdum ligula in, finibus tortor.Vivamus luctus eleifend urna eu venenatis.Etiam auctor egestas erat a maximus.Curabitur eu lectus nibh.Aliquam ullamcorper, purus ut ultricies pretium, magna ligula pulvinar ante, eu sagittis sapien enim nec tellus.Nullam vestibulum at nunc sed maximus.Lorem ipsum dolor sit amet, consectetur adipiscing elit."
		"\nEtiam sed tortor id diam congue aliquam ut in ligula.Curabitur porta, mauris vitae fermentum blandit, neque justo efficitur quam, eu consectetur velit eros in metus.Phasellus et bibendum nibh.Nam aliquam nec est at faucibus.Fusce eu auctor nulla.Pellentesque pellentesque mollis neque non egestas.Cras semper diam ligula, a condimentum dolor convallis ac.Pellentesque eros turpis, suscipit eget convallis ac, efficitur eget mauris.Sed commodo neque sit amet molestie ultrices.Pellentesque accumsan commodo neque, vel hendrerit risus fringilla sit amet.Suspendisse eu ligula ligula."
		"\nInteger eget dapibus lacus, eu imperdiet enim.Donec vitae consequat sem, ut volutpat neque.Donec feugiat elit sed nunc dignissim, ut ullamcorper orci ultricies.Aliquam tristique eros non porttitor hendrerit.Curabitur id vestibulum orci.Donec eu risus semper, facilisis ligula ultrices, pellentesque sem.Integer a metus quis nunc ornare sollicitudin et at ante.Nam aliquam rutrum quam, vel mollis libero blandit nec.Proin aliquam iaculis nibh, sed sagittis purus laoreet in.Sed volutpat lectus vel iaculis venenatis.";*/

		//simple test
	string plaintext = "This is a test";

	cout << "AES" << endl << endl;
	auto AES1 = runAES(plaintext);
	auto AES2 = runAES(plaintext);
	auto AES3 = runAES(plaintext);

	auto averageTimeAES = (AES1 + AES2 + AES3) / 3;
	cout << "Average time for AES: " << averageTimeAES.count() << " microseconds" << endl << endl;
	cout << "-----------------------------------------------------------------------" << endl << endl;

	cout << "3DES" << endl << endl;
	auto DES1 = run3DES(plaintext);
	auto DES2 = run3DES(plaintext);
	auto DES3 = run3DES(plaintext);

	auto averageTimeDES = (DES1 + DES2 + DES3) / 3;
	cout << "Average time for 3DES: " << averageTimeDES.count() << " microseconds" << endl << endl;
	cout << "-----------------------------------------------------------------------" << endl << endl;


	
	cout << "RSA" << endl << endl;
	auto RSA1 = runRSA(plaintext);
	auto RSA2 = runRSA(plaintext);
	auto RSA3 = runRSA(plaintext);
	auto RSA4 = runRSA(plaintext);

	auto averageTimeRSA = (RSA1 + RSA2 + RSA3 + RSA4) / 4;
	cout << "Average time for RSA: " << averageTimeRSA.count() << " microseconds" << endl << endl;
	cout << "-----------------------------------------------------------------------" << endl << endl;
}


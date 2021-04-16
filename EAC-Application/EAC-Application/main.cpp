#include <chrono>
#include <dsa.h>
#include <rsa.h>
#include <des.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <iostream>

using namespace std;
using namespace std::chrono;
using namespace CryptoPP;

int main()
{
	byte key[AES::DEFAULT_KEYLENGTH];
	byte initVector[AES::BLOCKSIZE];

	memset(key, 0xab, AES::DEFAULT_KEYLENGTH);
	memset(initVector, 0xcd, AES::BLOCKSIZE);

	//we used a complex and long plaintext to capture reality
	string plaintext =	"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras eget neque sed nibh pellentesque consectetur. Duis condimentum nulla luctus odio placerat, quis condimentum lectus mollis. Nam iaculis tempor leo, ac porttitor metus mattis sit amet. Nulla id ligula a magna mollis aliquam vel nec orci. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Pellentesque imperdiet eleifend cursus. In non ipsum sit amet risus ultrices porta id vel nisi. Nam suscipit auctor dui. Donec efficitur tincidunt lobortis. Donec quis massa lobortis dui malesuada pharetra. Phasellus sit amet augue ac erat varius ultrices."
						"\nSed massa urna, euismod id nisi non, imperdiet tempus tellus.Donec venenatis eu sem quis commodo.Suspendisse sit amet nulla justo.Morbi nec ipsum tristique, congue lectus ut, porta leo.Aliquam varius blandit sapien, eget ornare neque aliquet a.Quisque congue pulvinar leo vitae convallis.Nam vitae ligula quis sem faucibus vestibulum." 
						"\nMauris sapien tellus, consequat eget aliquet a, blandit nec augue.Praesent a sem id sapien iaculis facilisis eget eu lectus.Donec quis rhoncus nulla, sit amet sodales est.Sed venenatis porta iaculis.Praesent maximus sit amet massa eget bibendum.Morbi augue mauris, tincidunt id diam et, accumsan vestibulum nisi.Mauris ut rhoncus nibh.Lorem ipsum dolor sit amet, consectetur adipiscing elit.Proin in metus rutrum, interdum ligula in, finibus tortor.Vivamus luctus eleifend urna eu venenatis.Etiam auctor egestas erat a maximus.Curabitur eu lectus nibh.Aliquam ullamcorper, purus ut ultricies pretium, magna ligula pulvinar ante, eu sagittis sapien enim nec tellus.Nullam vestibulum at nunc sed maximus.Lorem ipsum dolor sit amet, consectetur adipiscing elit."
						"\nEtiam sed tortor id diam congue aliquam ut in ligula.Curabitur porta, mauris vitae fermentum blandit, neque justo efficitur quam, eu consectetur velit eros in metus.Phasellus et bibendum nibh.Nam aliquam nec est at faucibus.Fusce eu auctor nulla.Pellentesque pellentesque mollis neque non egestas.Cras semper diam ligula, a condimentum dolor convallis ac.Pellentesque eros turpis, suscipit eget convallis ac, efficitur eget mauris.Sed commodo neque sit amet molestie ultrices.Pellentesque accumsan commodo neque, vel hendrerit risus fringilla sit amet.Suspendisse eu ligula ligula."
						"\nInteger eget dapibus lacus, eu imperdiet enim.Donec vitae consequat sem, ut volutpat neque.Donec feugiat elit sed nunc dignissim, ut ullamcorper orci ultricies.Aliquam tristique eros non porttitor hendrerit.Curabitur id vestibulum orci.Donec eu risus semper, facilisis ligula ultrices, pellentesque sem.Integer a metus quis nunc ornare sollicitudin et at ante.Nam aliquam rutrum quam, vel mollis libero blandit nec.Proin aliquam iaculis nibh, sed sagittis purus laoreet in.Sed volutpat lectus vel iaculis venenatis.";
	
	string ciphertext;
	string decryptedtext;

	//encrypt
	AES::Encryption aesEncryption(key, AES::DEFAULT_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, initVector);

	StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();

	//print ciphertext
	cout << ciphertext << endl;

	//decrypt
	AES::Decryption aesDecryption(key, AES::DEFAULT_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, initVector);

	StreamTransformationFilter stfDecryptor(cbcDecryption, new StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
	stfDecryptor.MessageEnd();

	//print decryptedtext
	cout << decryptedtext << endl;
}
#include "helpers.h"

using namespace std;
using namespace seal;

int main(int argc, char const *argv[])
{
    #pragma region DEFINE_HE_PARAMETERS
    EncryptionParameters parms(scheme_type::BFV);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << endl;
    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    Encryptor encryptor(context, public_key);
    BatchEncoder batchEncoder(context);
    #pragma endregion;

    int x[] = {'H','E','L','L','O' ,'W','O','R','L','D','!'};
    int y[] = {'H','E','L','L','O' ,'W','O','R','L','D','!'};
    
    vector<uint64_t> x_vector(sizeof(x)/sizeof(int),0ull);
    vector<uint64_t> y_vector(sizeof(y)/sizeof(int),0ull);
    for (int i = 0; i < sizeof(x)/sizeof(int); i++)
    {
        x_vector[i] = x[i];
        y_vector[i] = y[i];
    }
    cout << "X = ";
    for (int i = 0; i < sizeof(x)/sizeof(int); i++)
    {
        cout << (char)x_vector[i];
    }
    cout <<endl;
    cout << "Y = ";
    for (int i = 0; i < sizeof(x)/sizeof(int); i++)
    {
        cout << (char)y_vector[i];
    }
    cout <<endl;

    cout << "Size of x = " << sizeof(x_vector) <<endl;
    cout << "Size of y = " << sizeof(y_vector) <<endl;

    Plaintext plain_x, plain_y;

    batchEncoder.encode(x_vector,plain_x);
    batchEncoder.encode(y_vector,plain_y);
    cout<< "PLAINTEXT X = "<<endl;
    for (int i = 0; i < sizeof(plain_x.int_array())/sizeof(int); i++)
    {
        cout << plain_x.int_array()[i] <<",";
    }
    cout << endl;
    cout<< "PLAINTEXT Y = "<<endl;
    for (int i = 0; i < sizeof(plain_y.int_array())/sizeof(int); i++)
    {
        cout << plain_y.int_array()[i] <<",";
    }
    cout << endl;
    Ciphertext encrypted_x,encrypted_y;
    encryptor.encrypt(plain_x,encrypted_x);
    encryptor.encrypt(plain_y,encrypted_y);

    cout<< "ENCRYPTED X = "<<endl;
    for (int i = 0; i < sizeof(encrypted_x.int_array())/sizeof(int); i++)
    {
        cout << encrypted_x.int_array()[i] <<",";
    }
    cout << endl;
    cout<< "ENCRYPTED Y = "<<endl;
    for (int i = 0; i < sizeof(encrypted_x.int_array())/sizeof(int); i++)
    {
        cout << encrypted_y.int_array()[i] <<",";
    }
    cout << endl;
    cout << "Size of encrypted x = " <<sizeof(encrypted_x) << " and y = "
     <<sizeof(encrypted_y) <<endl;
      cout << "Size of encrypted x = " <<encrypted_x.size() << " and y = "
     << encrypted_y.size()<<endl;

    Ciphertext x_minus_y;
    evaluator.sub(encrypted_x,encrypted_y,x_minus_y);

    Plaintext decrypted_x, decrypted_y, decrypted_x_minus_y;
    decryptor.decrypt(encrypted_x,decrypted_x);
    decryptor.decrypt(encrypted_y,decrypted_y);
    decryptor.decrypt(x_minus_y,decrypted_x_minus_y);

    cout<< "DECRYPTED X = "<<endl;
    for (int i = 0; i < sizeof(decrypted_x.int_array())/sizeof(int); i++)
    {
        cout << decrypted_x.int_array()[i] <<",";
    }
    cout <<endl;
    cout<< "DECRYPTED Y = "<<endl;
    for (int i = 0; i < sizeof(decrypted_y.int_array())/sizeof(int); i++)
    {
        cout << decrypted_y.int_array()[i] <<",";
    }
    cout <<endl;
    cout<< "DECRYPTED X_MINUS_Y = "<<endl;
    for (int i = 0; i < sizeof(decrypted_x_minus_y.int_array())/sizeof(int); i++)
    {
        cout << decrypted_x_minus_y.int_array()[i] <<",";
    }
    cout << endl;
    cout << "Size of decrypted x = " <<sizeof(encrypted_x) << " and y = "
     <<sizeof(decrypted_x) <<endl;
    cout << "Size of decrypted y = " <<sizeof(decrypted_y) << " and y = "
     <<sizeof(decrypted_y) <<endl;
     cout << "Size of decrypted x_minus_y = " <<sizeof(decrypted_x_minus_y) << " and y = "
     <<sizeof(decrypted_x_minus_y) <<endl;

    vector<uint64_t> x_vector_decoded(sizeof(x)/sizeof(int),0ull);
    vector<uint64_t> y_vector_decoded(sizeof(y)/sizeof(int),0ull);

    batchEncoder.decode(decrypted_x,x_vector_decoded);
    batchEncoder.decode(decrypted_y,y_vector_decoded);


    for (int i = 0; i < sizeof(x)/sizeof(int); i++)
    {
        cout << (char)x_vector_decoded[i];
    }
    cout <<endl;
    cout <<"ARE THESE TWO STRINGS ARE EQUAL: "<< decrypted_x_minus_y.is_zero() <<endl;
    return 0;
}

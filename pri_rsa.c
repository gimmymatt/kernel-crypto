/** test rsa API function
* sign&verify
*
*/

#define DEBUG

#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>  
#include <crypto/rng.h>
#include <crypto/drbg.h>
#include <crypto/akcipher.h>
#include <linux/base64.h>
#include "rsa_test.h"

static void hexdump(unsigned char *buf, unsigned int len)
{
        print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,
                        16, 1,
                        buf, len, false);
}


static int rsa_init(void)

{
    int err=0;
    struct crypto_akcipher *tfm;    
    struct akcipher_request *req;
    struct scatterlist src, dst;
    void *inbuf_enc =NULL;
    void *inbuf_dec = NULL;
    void *outbuf_enc = NULL;
    void *outbuf_dec = NULL;
    unsigned int out_len_max, out_len = 0;
 
    tfm = crypto_alloc_akcipher("rsa", 0, 0);
    if (IS_ERR(tfm)) {
          pr_err("alg: akcipher: Failed to load tfm for %s: %ld\n",
                       0, PTR_ERR(tfm));
          return PTR_ERR(tfm);
    }
    // alloc akcipher req
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
	pr_err("rsa: akcipher: Failed to alloc request:%s",PTR_ERR(req));
	goto free_akcipher;
    }

     //set the pub key
    err = crypto_akcipher_set_pub_key(tfm, pub_key_der,pub_key_der_len);
    if(err) {

	pr_err("set pub key err!");
    	goto free_req;
    }
    // alloc buf
    out_len_max = crypto_akcipher_maxsize(tfm);
    pr_debug("akcipher max output:%x\n", out_len_max);
    outbuf_dec = kzalloc(out_len_max, GFP_KERNEL);
    inbuf_dec  = kzalloc( priveta_en_len , GFP_KERNEL);
    if (!outbuf_dec || !inbuf_dec)
    	goto free_req;
    memcpy(inbuf_dec, priveta_en, priveta_en_len);
    //
    sg_init_one(&src, inbuf_dec, priveta_en_len); 
    pr_debug("inbuf:\n");
    hexdump(inbuf_dec,priveta_en_len);
    sg_init_one(&dst, outbuf_dec, out_len_max); 
    akcipher_request_set_crypt(req, &src, &dst, priveta_en_len, out_len_max);
    //akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,tcrypt_complete, &result);

    /* Run RSA decrypt - c = m^e mod n;*/
    //err = crypto_akcipher_decrypt(req);
    err = crypto_akcipher_verify(req);
    if (err) {
        pr_err("alg: rsa: decrypt test failed. err %d\n", err);
        goto free_xbuf;
    }
    pr_debug("outbuf:\n");
    hexdump(outbuf_dec,256);

    // encryption : sign
    err = crypto_akcipher_set_priv_key(tfm, private_der, private_der_len);
    if(err) 
	goto free_xbuf;
    out_len_max = crypto_akcipher_maxsize(tfm);
    pr_debug("akcipher max output:%x\n", out_len_max);

    outbuf_enc = kzalloc(out_len_max, GFP_KERNEL);
    inbuf_enc  = kzalloc( 6 , GFP_KERNEL);
    if (!outbuf_enc || !inbuf_enc)
    	goto free_xbuf;

    sg_init_one(&src, inbuf_enc, 6); 
    memcpy(inbuf_enc,m,6);
    pr_debug("encrypt in:\n");
    hexdump(inbuf_enc, 6);

    sg_init_one(&dst, outbuf_enc, 256); 
    akcipher_request_set_crypt(req, &src, &dst, 6, 256);
    //err = crypto_akcipher_encrypt(req);
    err = crypto_akcipher_sign(req);
    if (err) {
    	pr_err("alg: rsa: encrypt test failed. err %d\n", err);
        goto free_all;
    }
    pr_debug("crypt out:\n");
    hexdump(outbuf_enc,256);
free_all:
        kfree(inbuf_enc);
        kfree(outbuf_enc);
free_xbuf:
        kfree(inbuf_dec);
        kfree(outbuf_dec);
free_req:
        akcipher_request_free(req);
free_akcipher:
    	crypto_free_akcipher(tfm);
    return err;
}

static void rsa_exit(void)
{

}

module_init(rsa_init);
module_exit(rsa_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RSA generic algorithm test");

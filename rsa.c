/** test rsa API function
*
*
*/


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
#include "rsa_test.h"



static int rsa_init(void)
{
    int err=0;
    struct crypto_akcipher *tfm;    
    struct akcipher_request *req;
    
    tfm = crypto_alloc_akcipher("rsa", 0, 0);
    if (IS_ERR(tfm)) {
          pr_err("alg: akcipher: Failed to load tfm for %s: %ld\n",
                       0, PTR_ERR(tfm));
          return PTR_ERR(tfm);
    }
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
	pr_err("rsa: akcipher: Failed to alloc request:%s",PTR_ERR(req));
	goto free_akcipher;
    }

     //set the key
    err = crypto_akcipher_set_pub_key(tfm, pub_key_der,pub_key_der_len);
    if(err) {
	pr_err("set pub key err!");
    	goto free_req;
    }

free_all:
        //kfree(outbuf_dec);
        //kfree(outbuf_enc);
free_req:
        akcipher_request_free(req);
free_xbuf:
        //testmgr_free_buf(xbuf);
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

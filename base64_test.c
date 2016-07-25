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


static int base64_init(void)
{
    int err = 0;
    struct crypto_akcipher *tfm; 
    struct akcipher_request *req;
    char  *unbase64 = NULL;
    size_t unbase64_len;
    void *outbuf_dec = NULL;
    struct scatterlist src, dst;
    unsigned int out_len_max, out_len = 0;

    unbase64 = base64_decode(__4823DB8A2FD3_b3000013c7b63801_bin, __4823DB8A2FD3_b3000013c7b63801_bin_len, &unbase64_len);
    if ( unbase64 == NULL ) {
	pr_err("base64_decode error\n");
	return -1;
    }
   hexdump(unbase64, unbase64_len);

   // decrypt
    tfm = crypto_alloc_akcipher("rsa", 0, 0);
    if (IS_ERR(tfm)) {
          pr_err("alg: akcipher: Failed to load tfm for %s: %ld\n",
                       0, PTR_ERR(tfm));
	  err = PTR_ERR(tfm);
          goto free_base64;
    }
    
    // alloc akcipher req
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("rsa: akcipher: Failed to alloc request:%s",PTR_ERR(req));
	err = -1;
        goto free_akcipher;
    }
     //set the pub key
    err = crypto_akcipher_set_pub_key(tfm, public_der,public_der_len);
    if(err) {
        pr_err("set pub key err!");
        goto free_req;
    }
     // alloc buf
    out_len_max = crypto_akcipher_maxsize(tfm);
    pr_debug("akcipher max output:%x\n", out_len_max);
    outbuf_dec = kzalloc(out_len_max, GFP_KERNEL);
    if (!outbuf_dec )
        goto free_req;
    
    sg_init_one(&src, unbase64, unbase64_len);
    pr_debug("inbuf:\n");
    hexdump(unbase64, unbase64_len);
    sg_init_one(&dst, outbuf_dec, out_len_max);
    akcipher_request_set_crypt(req, &src, &dst, unbase64_len, out_len_max);

    err = crypto_akcipher_verify(req);
    if (err) {
        pr_err("alg: rsa: decrypt test failed. err %d\n", err);
        goto free_xbuf;
    }
    pr_debug("outbuf:\n");
    hexdump(outbuf_dec,out_len_max);

free_xbuf:
        kfree(outbuf_dec);
free_req:
        akcipher_request_free(req);
free_akcipher:
        crypto_free_akcipher(tfm);
free_base64:
    kfree(unbase64);
    return err;
}
static void base64_exit(void)
{

}

module_init(base64_init);
module_exit(base64_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RSA generic algorithm test");

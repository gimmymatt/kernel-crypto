/** template
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




static int module_init(void)
{
        return crypto_register_akcipher(&rsa);
}

static void module_exit(void)
{
        crypto_unregister_akcipher(&rsa);
}

module_init(module_init);
module_exit(module_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("template");

//Used to be electra but we scrapped electras code.


#include <Foundation/Foundation.h>

int injectTrustCache(NSArray <NSString*> *files, uint64_t trust_chain, int (*pmap_load_trust_cache)(uint64_t, size_t));

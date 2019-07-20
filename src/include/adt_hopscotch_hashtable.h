
#ifndef SRC_INCLUDE_ADT_HOPSCOTCH_HASHTABLE_H_
#define SRC_INCLUDE_ADT_HOPSCOTCH_HASHTABLE_H_


/*_
 * Copyright (c) 2016 Hirochika Asai <asai@jar.jp>
 * With modifications Copyright (C) 2015-2019 unfacd works
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


//#define HOPSCOTCH_INIT_BSIZE_FACTOR     6 //64 buckets
#define HOPSCOTCH_HOPINFO_SIZE          32
#define ITEM_EXTRACTOR_UNDEFINED NULL

typedef ClientContextData * (*ItemExtractor)(ItemContainer *);

//based on http://codecapsule.com/2013/08/11/hopscotch-hashing/
struct hopscotch_bucket {
    void *data;
    uint32_t hopinfo;
};
struct HopscotchHashtable {
    size_t pfactor;//changes per resize
    struct hopscotch_bucket *buckets;//changes per resize
};
typedef struct HopscotchHashtable HopscotchHashtable;

typedef struct  HopscotchHashtableConfigurable {
			HopscotchHashtable hashtable;
	    size_t keylen;
	    size_t key_offset;
	    uint64_t (*hash_func)(uint8_t *, size_t);
} HopscotchHashtableConfigurable;


typedef UFSRVResult *(*CallbackExecutor)(ClientContextData *, ClientContextData *payload);

typedef void(*CallbackFinaliser)(ClientContextData *);

struct HopscotchHashtable *
hopscotch_init(HopscotchHashtable *, size_t);
void hopscotch_release(HopscotchHashtable *);
void *hopscotch_lookup(HopscotchHashtable *, ItemExtractor extractor_ptr, uint8_t *, size_t);
void *hopscotch_lookup_configurable (HopscotchHashtableConfigurable *htc, uint8_t *key);
int hopscotch_insert(HopscotchHashtable *, ItemExtractor extractor_ptr, void *, size_t);
int hopscotch_insert_configurable (HopscotchHashtableConfigurable *htc, uint8_t *data);
void *hopscotch_remove(HopscotchHashtable *, ItemExtractor extractor_ptr, uint8_t *, size_t);
void *hopscotch_remove_configurable (HopscotchHashtableConfigurable *htc, uint8_t *key);

void *hopscotch_iterator_executor_configurable(HopscotchHashtableConfigurable *htc, CallbackExecutor executor_ptr, ClientContextData *ctx_ptr);
void *hopscotch_iterator_executor (HopscotchHashtable *ht, CallbackExecutor executor_ptr, ClientContextData *ctx_ptr);
void *hopscotch_iterator_finaliser (HopscotchHashtable *ht, CallbackFinaliser executor_ptr);

static inline bool IsHopscotchHashtableAllocated (HopscotchHashtable *ht_ptr) {
	return (IS_PRESENT(ht_ptr->buckets));
}

static inline size_t GetHopscotchHashtableAllocatedSize (HopscotchHashtable *ht_ptr) {
	return 1UL << ht_ptr->pfactor;
}

#endif /* SRC_INCLUDE_ADT_HOPSCOTCH_HASHTABLE_H_ */

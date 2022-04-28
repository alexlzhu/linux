// SPDX-License-Identifier: GPL-2.0
/*
 * Verification of builtin signatures
 *
 * Copyright 2019 Google LLC
 */

#include "fsverity_private.h"

#include <linux/cred.h>
#include <linux/key.h>
#include <linux/slab.h>
#include <linux/verification.h>

extern int fsverity_require_signatures;

/*
 * Keyring that contains the trusted X.509 certificates.
 *
 * Only root (kuid=0) can modify this.  Also, root may use
 * keyctl_restrict_keyring() to prevent any more additions.
 */
static struct key *fsverity_keyring;

/**
 * fsverity_verify_signature() - check a verity file's signature
 * @vi: the file's fsverity_info
 * @signature: the file's built-in signature
 * @sig_size: size of signature in bytes, or 0 if no signature
 *
 * If the file includes a signature of its fs-verity file digest, verify it
 * against the certificates in the fs-verity keyring.
 *
 * Return: 0 on success (signature valid or not required); -errno on failure
 */
int fsverity_verify_signature(const struct fsverity_info *vi,
			      const u8 *signature, size_t sig_size)
{
	const struct inode *inode = vi->inode;
	const struct fsverity_hash_alg *hash_alg = vi->tree_params.hash_alg;
	struct fsverity_formatted_digest *d;
	int err;

	if (sig_size == 0) {
		err = 0;
		if (fsverity_require_signatures) {
			fsverity_err(inode,
				     "require_signatures=1, rejecting unsigned file!");
			if (fsverity_enforced()) {
				err = -EPERM;
			} else {
				fsverity_warn(vi->inode, "AUDIT ONLY. ignore unsigned");
				err = 0;
			}
		}
		return err;
	}

	d = kzalloc(sizeof(*d) + hash_alg->digest_size, GFP_KERNEL);
	if (!d)
		return -ENOMEM;
	memcpy(d->magic, "FSVerity", 8);
	d->digest_algorithm = cpu_to_le16(hash_alg - fsverity_hash_algs);
	d->digest_size = cpu_to_le16(hash_alg->digest_size);
	memcpy(d->digest, vi->file_digest, hash_alg->digest_size);

	err = verify_pkcs7_signature(d, sizeof(*d) + hash_alg->digest_size,
				     signature, sig_size, fsverity_keyring,
				     VERIFYING_UNSPECIFIED_SIGNATURE,
				     NULL, NULL);
	kfree(d);

	if (err) {
		if (err == -ENOKEY)
			fsverity_err(inode,
				     "File's signing cert isn't in the fs-verity keyring");
		else if (err == -EKEYREJECTED)
			fsverity_err(inode, "Incorrect file signature");
		else if (err == -EBADMSG)
			fsverity_err(inode, "Malformed file signature");
		else
			fsverity_err(inode, "Error %d verifying file signature",
				     err);
		if (!fsverity_enforced()) {
			fsverity_warn(vi->inode, "AUDIT ONLY. ignore signature error");
			err = 0;
		}
		return err;
	}

	pr_debug("Valid signature for file digest %s:%*phN\n",
		 hash_alg->name, hash_alg->digest_size, vi->file_digest);
	return 0;
}

int __init fsverity_init_signature(void)
{
	struct key *ring;

	ring = keyring_alloc(".fs-verity", KUIDT_INIT(0), KGIDT_INIT(0),
			     current_cred(), KEY_POS_SEARCH |
				KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE |
				KEY_USR_SEARCH | KEY_USR_SETATTR,
			     KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(ring))
		return PTR_ERR(ring);

	fsverity_keyring = ring;
	return 0;
}

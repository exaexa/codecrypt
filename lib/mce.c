
#include "codecrypt.h"
#include "math.h"
#include "tools.h"

int ccr_mce_gen (struct ccr_mce_pubkey* Pub, struct ccr_mce_privkey* Priv)
{
	/* params are taken from privkey matrix */

	int ret;
	int m;
	ccr_mtx h;
	int h_cols, h_rows;

	/* param n must be power of 2 */
	if (ccr_log2 (Priv->n, &m) ) {
		ret = 1;
		goto fail;
	}

	/* check sanity of t param, k<=n-mt */
	if (Priv->n >= m * Priv->t) {
		ret = 2;
		goto fail;
	}

	/* allocate space for goppa polynomial */
	Priv->poly = ccr_malloc (ccr_mtx_alloc_size (t + 1, 1) );
	if (!Priv->poly) {
		ret = 3;
		goto fail;
	}

	/* generate the polynomial */
	if (ccr_gen_irred_poly (Priv->poly, Priv->t) ) {
		ret = 4;
		goto fail_free_poly;
	}

	/* create canonical check matrix */
	if (ccr_goppa_check_mtx (Priv->poly, m, Priv->t, &h, &h_cols, &h_rows) ) {
		ret = 5;
		goto fail_free_poly;
	}

	if(ccr_goppa_systematic_form(h,h_cols,h_rows,

	return 0;

fail_free_poly:
	ccr_free (Priv->poly);
fail:
	return ret;
}


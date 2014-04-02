
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

int main (int argc, char**argv)
{
	int param;
	char *output;
	mp_exp_t exp;
	mpf_t sqrt;

	if (argc < 2 ||
	    1 != sscanf (argv[1], "%d", &param) ||
	    param < 2) return 1;

	mpf_set_default_prec (100000);
	mpf_init (sqrt);
	mpf_sqrt_ui (sqrt, param);

	output = mpf_get_str (NULL, &exp, 16, 0, sqrt);
	printf ("%.*s.%s\n", (int) exp, output, output + exp);

	free (output);
	mpf_clear (sqrt);

	return 0;
}

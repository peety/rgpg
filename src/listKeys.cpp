
#include <Rcpp.h>
#include <gpgme.h>
#include <stdlib.h>

void fail_on_err(gpgme_error_t err) {
  Rcpp::stop(gpgme_strerror(err));
  exit(1);
}

//' listKeys -- Print out information for all secret keys
//' @example getKeys()
// [[Rcpp::export]]
void listKeys() {
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_key_t key;
  gpgme_user_id_t uid;
  std::vector<std::string> keys;

  // initialize gpgme
  gpgme_check_version(NULL);

  // create context
  if ((err = gpgme_new(&ctx))) fail_on_err(err);

  // initialize key listing
  if ((err = gpgme_op_keylist_start(ctx, NULL, 1))) fail_on_err(err);

  // get all keys
  while (!(err = gpgme_op_keylist_next(ctx, &key))) {
    uid = key->uids;
    Rcpp::Rcout
      << key->subkeys->keyid + 8
      << ": "
      << (uid && uid->name ? uid->name : "")
      << " <"
      << (uid && uid->email ? uid->email : "")
      << ">"
      << std::endl;
    while ((uid = uid->next)) {
      Rcpp::Rcout
        << "\t"
        << (uid->name ? uid->name : "")
        << " <"
        << (uid->email ? uid->email : "")
        << ">"
        << std::endl;
    }
  }
    
  if (gpgme_err_code(err) != GPG_ERR_EOF) fail_on_err(err);

  // end key listing
  gpgme_op_keylist_end(ctx);

  // release context
  gpgme_release(ctx);
}

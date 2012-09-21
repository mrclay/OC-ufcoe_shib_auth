# Shibboleth Auth for ownCloud

Warning, this is tailored for the UF College of Education's needs. To use this in another context you would definitely need to alter it.

It also must be placed in the root of the ownCloud install.

## Why not in /apps?

I'd prefer that it would be, but ownCloud's design and my own requirements make this difficult.

1. I don't want to enable lazy Shibboleth sessions on the entire webroot, which hurts performance, so I need to execute a PHP script which lives within the /apps directory.
2. ownCloud's mod_rewrite causes all PHP files in /apps to be handled by the root /index.php. So Shibboleth protection won't be triggered!
3. The only way to execute a PHP file in /apps directly seems to be to rely on Apache MultiViews, which allows a request for "/apps/foo/bar/" to execute /apps/foo/bar.php without the RewriteRules being applied. I'd prefer not to add that requirement, and this seems like a quirk anyway, so this won't do.

# Gem name is "cru-iap"; the namespace is Cru::Iap. Bundler.require derives
# the require path from the gem name, so give it a file to find — otherwise
# every Rails consumer needs `require: "cru/iap"` in its Gemfile.
require_relative "cru/iap"

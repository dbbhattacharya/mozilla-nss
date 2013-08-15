For now, this should be considered a sketch, not something that's quite complete or ready to be considered for merging. The last full test run I did had a bunch broken, and while I made some changes that will help fix them, I doubt I fixed them all, and I'm not waiting for a full test run before pushing this, because I know it's not at that stage anyway.

In particular:

* Expose public functions that take a PRFileDesc and do things that are currently only doable if you have the corresponding sslSocket*. Until we do this, client-supplied senders can't actually do anything, even send fixed data.
* Consider simplifying handler code by changing the builtin ones to be of type SSL_HelloExtensionHandlerFunc and dumping all the Abstract stuff. This is basically what I did when doing the Sender stuff, and it made things way better. I expect to have to change one or the other for continuity, so we should figure out which way we want to do it and then I'll change accordingly.
* Style--Right now, the internal names for the handler stuff doesn't fit the style at all. A lot of lines are too long. Some whitespace is bad (only in places where I inherited inconsistent spacing). Will fix. Also, some names are really long, but I'm not sure what to do about that.
* Make existing tests pass
* Write tests

Some Challenges:

* Public interface--eg. how much of the stuff in sslSocket might an extension handler/sender need to touch?
* Balance between simplicity of the new functionality vs. keeping it separate from the new functionality. Eg. the question of whether to change all the existing callbacks to the public type signature to make that easier.
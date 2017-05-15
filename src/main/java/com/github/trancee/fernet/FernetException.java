package com.github.trancee.fernet;

import java.security.GeneralSecurityException;

public class FernetException extends GeneralSecurityException {
	private static final long serialVersionUID = 1L;

	public FernetException(String message) {
		super(message);
	}
	public FernetException(Exception exception) {
		super(exception);
	}
}

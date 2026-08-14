import { Request, Response } from 'express';
import { errorHandler, notFoundHandler } from '../../src/middleware/errorHandler';

function mockResponse(): Response {
  const res: Partial<Response> = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.headersSent = false;
  return res as Response;
}

describe('notFoundHandler', () => {
  it('responds with a 404 JSON error', () => {
    const res = mockResponse();
    notFoundHandler({} as Request, res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not found' });
  });
});

describe('errorHandler', () => {
  it('responds with a 500 JSON error when headers have not been sent', () => {
    const res = mockResponse();
    const next = jest.fn();
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    errorHandler(new Error('boom'), {} as Request, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal server error' });
    expect(next).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('delegates to next when headers were already sent', () => {
    const res = mockResponse();
    res.headersSent = true;
    const next = jest.fn();
    const err = new Error('boom');

    errorHandler(err, {} as Request, res, next);

    expect(next).toHaveBeenCalledWith(err);
    expect(res.status).not.toHaveBeenCalled();
  });

  it('logs a structured JSON error with method, path, and message', () => {
    const res = mockResponse();
    const next = jest.fn();
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const req = { method: 'GET', path: '/api/policies/1' } as Request;

    errorHandler(new Error('boom'), req, res, next);

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.objectContaining({ method: 'GET', path: '/api/policies/1', message: 'boom' }),
    );
    consoleSpy.mockRestore();
  });
});

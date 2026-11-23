def inspect_page(request, repository):
    page_size = min(int(request.params["size"]), 50)
    return repository.fetch_page(page_size)





def read_identity(token, jwt, trusted_key):
    return jwt.verify(token, trusted_key)






def preview_export(repository):
    return repository.load_unpaged()  # El contrato de esta muestra devuelve todas las filas.

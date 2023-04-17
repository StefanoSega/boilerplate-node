export interface Repository<T> {
  get(): Promise<Array<T>>;

  getById(id: string): Promise<T>;

  create(item: T);

  update(id: string, item: T);

  delete(id: string);
}

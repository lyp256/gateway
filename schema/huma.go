package schema

type Body[T any] struct {
	Body T
}

func NewBody[T any](body T) *Body[T] {
	return &Body[T]{
		Body: body,
	}
}

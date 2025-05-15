package plugins

// ISourceItem define a interface que um item deve implementar
type ISourceItem interface {
	GetContent() *string
	GetID() string
	GetSource() string
}

// Item é uma implementação concreta de ISourceItem
type Item struct {
	Content *string
	ID      string
	Source  string
}

// Implementando a interface ISourceItem
func (i *Item) GetContent() *string {
	return i.Content
}

func (i *Item) GetID() string {
	return i.ID
}

func (i *Item) GetSource() string {
	return i.Source
}
